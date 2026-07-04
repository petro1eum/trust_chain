"""Simple signer for TrustChain v2."""

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


@dataclass(frozen=True)
class SignedResponse:
    """A cryptographically signed response."""

    tool_id: str
    data: Any
    signature: str
    signature_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    nonce: Optional[str] = None
    parent_signature: Optional[str] = None  # Chain of Trust: link to previous step
    parent_signatures: Optional[list[str]] = None  # DAG Merges: multiple parents
    metadata: Optional[Dict[str, Any]] = None  # Signed contextual metadata
    certificate: Optional[Dict[str, Any]] = None  # Identity metadata

    # TSA (Timestamp Authority) proof - RFC 3161
    tsa_proof: Optional[Dict[str, Any]] = None  # TSAResponse.to_dict()

    # Attribution extensions (all optional; absent => legacy receipt, byte-identical).
    # Signed when present, so a verifier reads the STRENGTH of attribution, not a bool.
    signer_role: Optional[str] = None  # "tool" (executed) | "agent" (self-attested)
    custody: Optional[Dict[str, Any]] = None  # key custody: {"type": software|hard_kms}
    input_hash: Optional[str] = None  # "sha256:<hex>" of the canonical request
    alg: Optional[str] = None  # signature alg id (None => legacy implicit ed25519)
    canon: Optional[str] = None  # canonicalization scheme (None/"jcs"); None => legacy

    # Cache verification result
    _verified: Optional[bool] = field(default=None, init=False, repr=False)

    @property
    def is_verified(self) -> bool:
        """Check if response is verified (cached)."""
        return self._verified is True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "tool_id": self.tool_id,
            "data": self.data,
            "signature": self.signature,
            "signature_id": self.signature_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "parent_signature": self.parent_signature,
        }
        if self.parent_signatures is not None:
            result["parent_signatures"] = self.parent_signatures
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.certificate is not None:
            result["certificate"] = self.certificate
        if self.tsa_proof is not None:
            result["tsa_proof"] = self.tsa_proof
        if self.signer_role is not None:
            result["signer_role"] = self.signer_role
        if self.custody is not None:
            result["custody"] = self.custody
        if self.input_hash is not None:
            result["input_hash"] = self.input_hash
        if self.alg is not None:
            result["alg"] = self.alg
        if self.canon is not None:
            result["canon"] = self.canon
        return result


def _build_canonical_data(
    tool_id: str,
    data: Any,
    timestamp: float,
    nonce: Optional[str],
    parent_signature: Optional[str],
    parent_signatures: Optional[list[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    certificate: Optional[Dict[str, Any]] = None,
    tsa_proof: Optional[Dict[str, Any]] = None,
    signature_id: Optional[str] = None,
    signer_role: Optional[str] = None,
    custody: Optional[Dict[str, Any]] = None,
    input_hash: Optional[str] = None,
    alg: Optional[str] = None,
    canon: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the canonical payload covered by the signature."""
    canonical_data: Dict[str, Any] = {
        "tool_id": tool_id,
        "data": data,
        "timestamp": timestamp,
        "nonce": nonce,
        "parent_signature": parent_signature,
    }

    if signature_id is not None:
        canonical_data["signature_id"] = signature_id
    if parent_signatures is not None:
        canonical_data["parent_signatures"] = parent_signatures
    if metadata is not None:
        canonical_data["metadata"] = metadata
    if certificate is not None:
        canonical_data["certificate"] = certificate
    if tsa_proof is not None:
        canonical_data["tsa_proof"] = tsa_proof
    # Attribution extensions — included only when set, so legacy payloads are
    # byte-identical (sort_keys makes insertion order irrelevant).
    if signer_role is not None:
        canonical_data["signer_role"] = signer_role
    if custody is not None:
        canonical_data["custody"] = custody
    if input_hash is not None:
        canonical_data["input_hash"] = input_hash
    if alg is not None:
        canonical_data["alg"] = alg
    if canon is not None:
        canonical_data["canon"] = canon

    return canonical_data


def _canonical_bytes(
    canonical_data: Dict[str, Any], canon: Optional[str] = None
) -> bytes:
    """Serialize the canonical payload to the exact signed bytes.

    ``canon`` selects the scheme: ``None`` (or "json-sort-keys-minified") is the
    legacy default (``json.dumps`` sorted+minified, ensure_ascii); ``"jcs"`` is
    RFC 8785 JSON Canonicalization Scheme via the optional ``rfc8785`` package.
    """
    if canon == "jcs":
        try:
            import rfc8785
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "canon='jcs' requires the rfc8785 package: pip install trustchain[jcs]"
            ) from exc
        return rfc8785.dumps(canonical_data)
    if canon not in (None, "json-sort-keys-minified"):
        raise ValueError(f"unknown canonicalization scheme: {canon!r}")
    return json.dumps(canonical_data, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _canonical_json_from_response(
    response: SignedResponse,
    *,
    include_signature_id: bool,
) -> str:
    """Serialize canonical payload for verify (legacy omits signature_id)."""
    sid = response.signature_id if include_signature_id else None
    canonical_data = _build_canonical_data(
        tool_id=response.tool_id,
        data=response.data,
        timestamp=response.timestamp,
        nonce=response.nonce,
        parent_signature=response.parent_signature,
        parent_signatures=response.parent_signatures,
        metadata=response.metadata,
        certificate=response.certificate,
        tsa_proof=response.tsa_proof,
        signature_id=sid,
        signer_role=response.signer_role,
        custody=response.custody,
        input_hash=response.input_hash,
        alg=response.alg,
        canon=response.canon,
    )
    return _canonical_bytes(canonical_data, response.canon).decode("utf-8")


def canonical_input_hash(request: Any) -> str:
    """Stable hash of a tool request for request->response binding.

    Returns ``"sha256:<hex>"`` over the canonical JSON of ``request`` so a
    verifier can prove which input produced a signed output (catches the
    "agent fed a subtly wrong query, tool honestly signed the answer" case).
    """
    import hashlib

    payload = json.dumps(request, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_with_public_key(response: SignedResponse, public_key_b64: str) -> bool:
    """Verify a SignedResponse's Ed25519 signature against a SPECIFIC public key.

    Handles the ``canon`` scheme and the signature_id vintages. Used for
    cross-key verification — e.g. a tool-signed result checked against the tool's
    registered signing key — where the instance/agent key is not the signer.
    """
    if not HAS_CRYPTOGRAPHY:
        return False
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64)
        )
        signature_bytes = base64.b64decode(response.signature)
    except Exception:
        return False
    for include_sid in (True, False):
        try:
            json_data = _canonical_json_from_response(
                response, include_signature_id=include_sid
            )
            pub.verify(signature_bytes, json_data.encode("utf-8"))
            return True
        except Exception:
            continue
    return False


class Signer:
    """Simple signer for Ed25519 signatures."""

    def __init__(self, algorithm: str = "ed25519"):
        self.algorithm = algorithm
        self.key_id = str(uuid.uuid4())
        # Hard-KMS provider (HSM / cloud KMS); set only by from_provider().
        # When present the private seed is NOT in-process and signing is
        # delegated to provider.sign(). See trustchain.kms.KeyProvider.
        self._provider = None

        if algorithm == "ed25519":
            if not HAS_CRYPTOGRAPHY:
                raise RuntimeError(
                    "TrustChain requires the 'cryptography' package for Ed25519 signing."
                )
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            self._public_key = self._private_key.public_key()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def _raw_sign(self, payload: bytes) -> bytes:
        """Produce the raw Ed25519 signature over ``payload``.

        Delegates to the hard-KMS provider when one is wired (the seed never
        enters this process); otherwise signs with the in-process private key.
        """
        if self._provider is not None:
            return self._provider.sign(payload)
        return self._private_key.sign(payload)

    def _custody_descriptor(self) -> Dict[str, Any]:
        """Truthful key-custody descriptor derived from the signer itself.

        A caller cannot forge this: it reflects whether the private seed is in
        this process (``software``) or delegated to a hard-KMS/HSM provider
        (``hard_kms``), so an auditor reads the STRENGTH of the attribution.
        """
        if self._provider is not None:
            return {
                "type": "hard_kms",
                "key_id": self.key_id,
                "provider": type(self._provider).__name__,
            }
        return {"type": "software", "key_id": self.key_id}

    def sign(
        self,
        tool_id: str,
        data: Any,
        nonce: Optional[str] = None,
        parent_signature: Optional[str] = None,
        parent_signatures: Optional[list[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        certificate: Optional[Dict[str, Any]] = None,
        tsa_proof: Optional[Dict[str, Any]] = None,
        *,
        signer_role: Optional[str] = None,
        input_hash: Optional[str] = None,
        alg: Optional[str] = None,
        bind_custody: bool = False,
        canon: Optional[str] = None,
    ) -> SignedResponse:
        """Sign data and return SignedResponse.

        Attribution extensions (all opt-in; omitted => byte-identical legacy
        payload): ``signer_role`` ("tool"/"agent"), ``input_hash`` (bind the
        request via :func:`canonical_input_hash`), ``alg`` (algorithm id), and
        ``bind_custody`` which stamps a TRUTHFUL, signer-derived custody
        descriptor (software vs hard-KMS) that a caller cannot forge.
        """
        timestamp = time.time()
        resolved_nonce = nonce or str(uuid.uuid4())
        signature_id = str(uuid.uuid4())
        custody = self._custody_descriptor() if bind_custody else None

        # Create canonical representation.
        # parent_signatures (DAG multi-parent merges) is part of the signed
        # payload so that merge links are cryptographically protected, not
        # just recorded.
        canonical_data = _build_canonical_data(
            tool_id=tool_id,
            data=data,
            timestamp=timestamp,
            nonce=resolved_nonce,
            parent_signature=parent_signature,
            parent_signatures=parent_signatures,
            metadata=metadata,
            certificate=certificate,
            tsa_proof=tsa_proof,
            signature_id=signature_id,
            signer_role=signer_role,
            custody=custody,
            input_hash=input_hash,
            alg=alg,
            canon=canon,
        )

        # Serialize to the exact signed bytes (scheme selected by `canon`).
        signed_bytes = _canonical_bytes(canonical_data, canon)

        signature_bytes = self._raw_sign(signed_bytes)
        signature = base64.b64encode(signature_bytes).decode("ascii")

        response = SignedResponse(
            tool_id=tool_id,
            data=data,
            signature=signature,
            signature_id=signature_id,
            timestamp=timestamp,
            nonce=resolved_nonce,
            parent_signature=parent_signature,
            parent_signatures=parent_signatures,
            metadata=metadata,
            certificate=certificate,
            tsa_proof=tsa_proof,
            signer_role=signer_role,
            custody=custody,
            input_hash=input_hash,
            alg=alg,
            canon=canon,
        )
        object.__setattr__(response, "_verified", True)
        return response

    def verify(self, response: SignedResponse) -> bool:
        """Verify a signed response (v3.2+ binds signature_id; legacy without)."""
        try:
            signature_bytes = base64.b64decode(response.signature)
        except Exception:
            return False
        for include_sid in (True, False):
            try:
                json_data = _canonical_json_from_response(
                    response, include_signature_id=include_sid
                )
                self._public_key.verify(signature_bytes, json_data.encode("utf-8"))
                return True
            except Exception:
                continue
        return False

    def get_public_key(self) -> str:
        """Get the public key in base64 format."""
        public_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(public_bytes).decode("ascii")

    def get_key_id(self) -> str:
        """Get the key identifier."""
        return self.key_id

    def export_keys(self) -> dict:
        """Export keys for persistence.

        Returns:
            dict with type, key_id, and key material (base64 encoded)
        """
        if self._private_key is None:
            raise ValueError(
                "Cannot export keys from a hard-KMS signer — the private seed "
                "never leaves the provider (HSM/KMS). Use sign()/verify()."
            )
        # Export private key in raw format
        private_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return {
            "type": "ed25519",
            "key_id": self.key_id,
            "private_key": base64.b64encode(private_bytes).decode("ascii"),
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_keys(cls, key_data: dict) -> "Signer":
        """Restore signer from exported keys.

        Args:
            key_data: dict from export_keys()

        Returns:
            Signer instance with restored keys
        """
        signer = cls.__new__(cls)
        signer.algorithm = key_data.get("algorithm", "ed25519")
        signer.key_id = key_data["key_id"]
        signer._provider = None

        if key_data["type"] == "fallback":
            raise ValueError(
                "Legacy fallback keys are no longer supported for security reasons."
            )
        elif key_data["type"] == "ed25519":
            if not HAS_CRYPTOGRAPHY:
                raise ValueError("cryptography library required for Ed25519")
            private_bytes = base64.b64decode(key_data["private_key"])
            signer._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                private_bytes
            )
            signer._public_key = signer._private_key.public_key()
        else:
            raise ValueError(f"Unknown key type: {key_data['type']}")

        return signer

    @classmethod
    def from_provider(cls, provider: Any) -> "Signer":
        """Build a hard-KMS signer that delegates signing to ``provider``.

        For HSM / cloud-KMS keys the private seed never leaves the device, so
        ``provider.get_seed()`` raises and we cannot construct an in-process
        private key. Instead we hold only the public key (for verify /
        get_public_key) and route every signature through ``provider.sign()``.

        ``provider`` must satisfy ``trustchain.kms.KeyProvider`` (at least
        ``get_public_key`` / ``get_key_id`` / ``sign``).
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError(
                "TrustChain requires the 'cryptography' package for Ed25519 signing."
            )
        signer = cls.__new__(cls)
        signer.algorithm = "ed25519"
        signer.key_id = provider.get_key_id()
        signer._provider = provider
        signer._private_key = None
        signer._public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            provider.get_public_key()
        )
        return signer
