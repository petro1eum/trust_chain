"""Simple signer for TrustChain v2."""

import base64
import hashlib
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


@dataclass
class SignedResponse:
    """A cryptographically signed response."""

    tool_id: str
    data: Any
    signature: str
    signature_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    nonce: Optional[str] = None
    parent_signature: Optional[str] = None  # Chain of Trust: link to previous step
    metadata: Optional[Dict[str, Any]] = None  # Signed contextual metadata
    certificate: Optional[Dict[str, Any]] = None  # Identity metadata

    # TSA (Timestamp Authority) proof - RFC 3161
    tsa_proof: Optional[Dict[str, Any]] = None  # TSAResponse.to_dict()

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
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.certificate is not None:
            result["certificate"] = self.certificate
        if self.tsa_proof is not None:
            result["tsa_proof"] = self.tsa_proof
        return result


def _build_canonical_data(
    tool_id: str,
    data: Any,
    timestamp: float,
    nonce: Optional[str],
    parent_signature: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
    certificate: Optional[Dict[str, Any]] = None,
    tsa_proof: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical payload covered by the signature."""
    canonical_data: Dict[str, Any] = {
        "tool_id": tool_id,
        "data": data,
        "timestamp": timestamp,
        "nonce": nonce,
        "parent_signature": parent_signature,
    }

    if metadata is not None:
        canonical_data["metadata"] = metadata
    if certificate is not None:
        canonical_data["certificate"] = certificate
    if tsa_proof is not None:
        canonical_data["tsa_proof"] = tsa_proof

    return canonical_data


class Signer:
    """Simple signer for Ed25519 signatures."""

    def __init__(self, algorithm: str = "ed25519"):
        self.algorithm = algorithm
        self.key_id = str(uuid.uuid4())

        if algorithm == "ed25519":
            if not HAS_CRYPTOGRAPHY:
                raise RuntimeError(
                    "TrustChain requires the 'cryptography' package for Ed25519 signing."
                )
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            self._public_key = self._private_key.public_key()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def sign(
        self,
        tool_id: str,
        data: Any,
        nonce: Optional[str] = None,
        parent_signature: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        certificate: Optional[Dict[str, Any]] = None,
        tsa_proof: Optional[Dict[str, Any]] = None,
    ) -> SignedResponse:
        """Sign data and return SignedResponse."""
        timestamp = time.time()
        resolved_nonce = nonce or str(uuid.uuid4())

        # Create canonical representation
        canonical_data = _build_canonical_data(
            tool_id=tool_id,
            data=data,
            timestamp=timestamp,
            nonce=resolved_nonce,
            parent_signature=parent_signature,
            metadata=metadata,
            certificate=certificate,
            tsa_proof=tsa_proof,
        )

        # Serialize to JSON
        json_data = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))

        signature_bytes = self._private_key.sign(json_data.encode("utf-8"))
        signature = base64.b64encode(signature_bytes).decode("ascii")

        response = SignedResponse(
            tool_id=tool_id,
            data=data,
            signature=signature,
            timestamp=timestamp,
            nonce=resolved_nonce,
            parent_signature=parent_signature,
            metadata=metadata,
            certificate=certificate,
            tsa_proof=tsa_proof,
        )
        response._verified = True
        return response

    def verify(self, response: SignedResponse) -> bool:
        """Verify a signed response."""
        try:
            # Recreate canonical data
            canonical_data = _build_canonical_data(
                tool_id=response.tool_id,
                data=response.data,
                timestamp=response.timestamp,
                nonce=response.nonce,
                parent_signature=response.parent_signature,
                metadata=response.metadata,
                certificate=response.certificate,
                tsa_proof=response.tsa_proof,
            )

            # Serialize to JSON
            json_data = json.dumps(
                canonical_data, sort_keys=True, separators=(",", ":")
            )

            signature_bytes = base64.b64decode(response.signature)
            self._public_key.verify(signature_bytes, json_data.encode("utf-8"))
            return True

        except Exception:
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
