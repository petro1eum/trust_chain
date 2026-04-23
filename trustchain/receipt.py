"""
TrustChain Receipt — self-contained, portable proof-of-signature object.

A ``.tcreceipt`` is a small JSON document (+ optional PEM cert chain) which
packages everything a third party needs to *independently* verify that a
single tool-call or agent response was produced by a specific TrustChain
identity at a specific moment in time.

Design goals:

1. **Self-contained.** The receipt embeds the signed envelope, the public
   key used to sign it, and (optionally) the PKIX certificate chain and
   witness co-signatures. A verifier does not need access to the producing
   system.

2. **Portable.** A receipt is plain JSON. It can be pasted into Slack,
   attached to a ticket, displayed as QR, or loaded by the browser-based
   ``verify.html`` via WebCrypto.

3. **Stable format.** ``format == "tcreceipt"`` and ``version == 1`` form
   the contract. Future revisions bump ``version``; backward compat is the
   consumer's responsibility.

4. **No network required for the base verification.** Signature check is
   pure crypto. CRL/OCSP/witness-freshness checks are *optional* extras
   that a verifier may run when it has network access.

Minimal receipt anatomy::

    {
      "format": "tcreceipt",
      "version": 1,
      "issued_at": "2026-04-23T14:30:00Z",
      "envelope":  { <SignedResponse.to_dict() — the signed message> },
      "key": {
        "algorithm":     "ed25519",
        "key_id":        "a7f1...",
        "public_key_b64":"MCow..."
      },
      "identity":  null | { subject_cn, issuer_cn, cert_chain_pem[] },
      "witnesses": null | [ CoSignedTreeHead.to_dict(), ... ],
      "summary":   { "tool_id": ..., "timestamp_iso": ..., "signature_short": ... }
    }
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trustchain.v2.signer import SignedResponse, _build_canonical_data

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover — real deployments always have it.
    _HAS_CRYPTOGRAPHY = False


RECEIPT_FORMAT = "tcreceipt"
RECEIPT_VERSION = 1


# --------------------------------------------------------------------------- #
# Errors                                                                      #
# --------------------------------------------------------------------------- #


class ReceiptError(Exception):
    """Base class for all receipt-related errors."""


class ReceiptFormatError(ReceiptError):
    """The document is not a valid TrustChain receipt (version/shape mismatch)."""


class ReceiptVerificationError(ReceiptError):
    """Base verification failed (signature does not match the envelope)."""


# --------------------------------------------------------------------------- #
# Data classes                                                                #
# --------------------------------------------------------------------------- #


@dataclass
class ReceiptVerification:
    """Outcome of :meth:`Receipt.verify`.

    ``signature_ok`` is the ground truth. The other flags are ``None`` when
    the relevant material is absent from the receipt (so ``identity_ok is None``
    simply means "this receipt does not carry a PKIX identity").
    """

    valid: bool
    signature_ok: bool
    identity_ok: bool | None
    witnesses_ok: bool | None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "signature_ok": self.signature_ok,
            "identity_ok": self.identity_ok,
            "witnesses_ok": self.witnesses_ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


# --------------------------------------------------------------------------- #
# Receipt                                                                     #
# --------------------------------------------------------------------------- #


@dataclass
class Receipt:
    """In-memory representation of a ``.tcreceipt`` document.

    Construct via :func:`build_receipt` or :meth:`Receipt.load`. Serialize via
    :meth:`to_dict` / :meth:`to_json` / :meth:`save`.
    """

    envelope: dict[str, Any]
    key: dict[str, Any]
    issued_at: str
    identity: dict[str, Any] | None = None
    witnesses: list[dict[str, Any]] | None = None
    summary: dict[str, Any] | None = None
    version: int = RECEIPT_VERSION

    # ---------------- Serialization ---------------- #

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "format": RECEIPT_FORMAT,
            "version": self.version,
            "issued_at": self.issued_at,
            "envelope": self.envelope,
            "key": self.key,
            "summary": self.summary or _derive_summary(self.envelope),
        }
        if self.identity is not None:
            out["identity"] = self.identity
        if self.witnesses is not None:
            out["witnesses"] = self.witnesses
        return out

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(
            self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False
        )

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(self.to_json(), encoding="utf-8")
        return p

    # ---------------- Convenience ---------------- #

    @property
    def tool_id(self) -> str:
        return str(self.envelope.get("tool_id", ""))

    @property
    def signature(self) -> str:
        return str(self.envelope.get("signature", ""))

    @property
    def signature_short(self) -> str:
        sig = self.signature
        return sig[:8] + "…" if len(sig) > 8 else sig

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the canonical envelope JSON, hex.

        This is a stable identifier of the *receipt content* — two receipts
        that cover the same envelope produce the same fingerprint even if
        wrapped with different identity/witness extras.
        """
        canonical = _canonical_envelope_bytes(self.envelope)
        return hashlib.sha256(canonical).hexdigest()

    # ---------------- Verification ---------------- #

    def verify(
        self,
        *,
        expected_public_key_b64: str | None = None,
        verify_witnesses: bool = True,
        max_age_seconds: float | None = None,
    ) -> ReceiptVerification:
        """Verify the receipt end-to-end.

        Args:
            expected_public_key_b64: if supplied, the verifier rejects the
                receipt unless its embedded ``key.public_key_b64`` matches.
                Use this to pin a receipt to a trusted identity — otherwise
                you're verifying "the receipt is internally consistent",
                not "the receipt was signed by *that* entity".
            verify_witnesses: when False, skips witness signature checks
                (they still appear in ``to_dict``). Off by default only if
                the caller knows witnesses are validated elsewhere.
            max_age_seconds: if set, rejects envelopes whose ``timestamp``
                is older than this. Useful for short-lived receipts (login
                challenges, one-shot tool calls).

        Returns:
            :class:`ReceiptVerification`. ``valid`` is ``True`` iff the
            signature check passed *and* every optional sub-check that ran
            also passed.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # ---- 1. Format sanity ---- #
        if self.version != RECEIPT_VERSION:
            errors.append(f"Unsupported receipt version {self.version}")
            return ReceiptVerification(
                valid=False,
                signature_ok=False,
                identity_ok=None,
                witnesses_ok=None,
                errors=errors,
                warnings=warnings,
            )

        # ---- 2. Pin identity if requested ---- #
        pk_b64 = self.key.get("public_key_b64")
        if not pk_b64:
            errors.append("key.public_key_b64 missing")
            return ReceiptVerification(
                valid=False,
                signature_ok=False,
                identity_ok=None,
                witnesses_ok=None,
                errors=errors,
                warnings=warnings,
            )

        if expected_public_key_b64 and expected_public_key_b64 != pk_b64:
            errors.append(
                "public_key_b64 pinning failed — receipt was signed by a different key"
            )
            # Still run the signature check; caller may want the detail.

        # ---- 3. Signature ---- #
        signature_ok = _verify_envelope_signature(self.envelope, pk_b64, errors)

        # ---- 4. Freshness ---- #
        if max_age_seconds is not None:
            ts = self.envelope.get("timestamp")
            if isinstance(ts, (int, float)):
                age = time.time() - float(ts)
                if age > max_age_seconds:
                    errors.append(
                        f"envelope is {age:.0f}s old, max_age_seconds={max_age_seconds:.0f}"
                    )

        # ---- 5. Identity (soft — PKIX chain verification is optional) ---- #
        identity_ok: bool | None = None
        if self.identity is not None:
            chain_pem = self.identity.get("cert_chain_pem") or []
            if not isinstance(chain_pem, list) or not chain_pem:
                warnings.append("identity present but cert_chain_pem is empty")
                identity_ok = False
            else:
                # Soft check: chain parses as PEM. Full PKIX/CRL validation
                # is done by `tc-verify --strict`; the receipt layer stays
                # pure-crypto so it works in a browser without an OpenSSL
                # chain.
                identity_ok = all(
                    isinstance(p, str) and "BEGIN CERTIFICATE" in p for p in chain_pem
                )
                if not identity_ok:
                    errors.append("identity.cert_chain_pem contains non-PEM entries")

        # ---- 6. Witnesses (soft) ---- #
        witnesses_ok: bool | None = None
        if self.witnesses is not None:
            if not isinstance(self.witnesses, list) or not self.witnesses:
                witnesses_ok = False
                errors.append("witnesses present but empty/malformed")
            elif verify_witnesses:
                try:
                    from trustchain.v2 import witness as witness_mod

                    # Extract the SignedTreeHead fields from each co-sign.
                    all_ok = True
                    for w in self.witnesses:
                        cosigned = witness_mod.CoSignedTreeHead.from_dict(w)
                        try:
                            witness_mod.verify_cosigned(cosigned)
                        except witness_mod.WitnessError as exc:
                            errors.append(f"witness {cosigned.witness_id}: {exc}")
                            all_ok = False
                    witnesses_ok = all_ok
                except Exception as exc:  # pragma: no cover — defensive
                    witnesses_ok = False
                    errors.append(f"witness verification crashed: {exc}")

        valid = (
            signature_ok
            and (identity_ok is not False)
            and (witnesses_ok is not False)
            and not errors
        )
        return ReceiptVerification(
            valid=valid,
            signature_ok=signature_ok,
            identity_ok=identity_ok,
            witnesses_ok=witnesses_ok,
            errors=errors,
            warnings=warnings,
        )

    # ---------------- Loaders ---------------- #

    @classmethod
    def load(cls, source: str | Path | dict[str, Any]) -> Receipt:
        """Load a receipt from a file path, JSON string, or dict.

        Accepted inputs:

        * ``Path`` or ``str`` that points to an existing file → read JSON
          from disk.
        * ``str`` that is not an existing file → parsed as JSON.
        * ``dict`` → treated as already-parsed document.
        """
        if isinstance(source, dict):
            return cls._from_dict(source)

        if isinstance(source, Path):
            data = json.loads(source.read_text(encoding="utf-8"))
            return cls._from_dict(data)

        if isinstance(source, str):
            # Heuristic: JSON documents start with `{`/`[` after whitespace;
            # anything else we treat as a path. Avoids ``Path(long_json).is_file()``
            # exploding with "File name too long" on systems with small PATH_MAX.
            stripped = source.lstrip()
            if stripped.startswith(("{", "[")):
                data = json.loads(source)
            else:
                p = Path(source)
                try:
                    if p.is_file():
                        data = json.loads(p.read_text(encoding="utf-8"))
                    else:
                        data = json.loads(source)
                except OSError:
                    data = json.loads(source)
            return cls._from_dict(data)

        raise ReceiptFormatError(f"Unsupported source type: {type(source).__name__}")

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Receipt:
        if data.get("format") != RECEIPT_FORMAT:
            raise ReceiptFormatError(
                f"format != {RECEIPT_FORMAT!r} (got {data.get('format')!r}) — "
                "not a TrustChain receipt"
            )
        version = int(data.get("version", 0))
        if version < 1:
            raise ReceiptFormatError(f"Invalid receipt version: {version}")
        envelope = data.get("envelope")
        key = data.get("key")
        if not isinstance(envelope, dict) or not isinstance(key, dict):
            raise ReceiptFormatError("envelope/key must be objects")
        return cls(
            envelope=envelope,
            key=key,
            issued_at=str(data.get("issued_at") or _iso_now()),
            identity=data.get("identity"),
            witnesses=data.get("witnesses"),
            summary=data.get("summary"),
            version=version,
        )


# --------------------------------------------------------------------------- #
# Public helpers                                                              #
# --------------------------------------------------------------------------- #


def build_receipt(
    response: SignedResponse | dict[str, Any],
    public_key_b64: str,
    *,
    key_id: str | None = None,
    algorithm: str = "ed25519",
    identity: dict[str, Any] | None = None,
    witnesses: list[dict[str, Any]] | None = None,
) -> Receipt:
    """Assemble a ``Receipt`` from a signed response and the signing key.

    The *response* can be either a :class:`SignedResponse` instance or its
    ``.to_dict()`` representation — both flow through the same canonical
    serialization on verify, so they are interchangeable on the wire.

    ``public_key_b64`` is the raw Ed25519 public key, base64-encoded. This
    is what ``Signer.get_public_key()`` already returns.
    """
    envelope = (
        response.to_dict() if isinstance(response, SignedResponse) else dict(response)
    )

    receipt = Receipt(
        envelope=envelope,
        key={
            "algorithm": algorithm,
            "key_id": key_id,
            "public_key_b64": public_key_b64,
        },
        issued_at=_iso_now(),
        identity=identity,
        witnesses=witnesses,
        summary=_derive_summary(envelope),
    )
    return receipt


def verify_receipt(
    source: str | Path | dict[str, Any] | Receipt,
    **kwargs: Any,
) -> ReceiptVerification:
    """One-shot convenience: load + verify in a single call."""
    receipt = source if isinstance(source, Receipt) else Receipt.load(source)
    return receipt.verify(**kwargs)


# --------------------------------------------------------------------------- #
# Internals                                                                   #
# --------------------------------------------------------------------------- #


def _iso_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_envelope_bytes(envelope: dict[str, Any]) -> bytes:
    """Rebuild the exact byte sequence covered by the Ed25519 signature.

    Mirrors :func:`trustchain.v2.signer._build_canonical_data` + the
    canonical JSON dump with ``sort_keys=True, separators=(",", ":")``.
    Any divergence from that function = broken receipts for everyone, so
    we call the same helper.
    """
    canonical = _build_canonical_data(
        tool_id=envelope.get("tool_id"),
        data=envelope.get("data"),
        timestamp=envelope.get("timestamp"),
        nonce=envelope.get("nonce"),
        parent_signature=envelope.get("parent_signature"),
        metadata=envelope.get("metadata"),
        certificate=envelope.get("certificate"),
        tsa_proof=envelope.get("tsa_proof"),
    )
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_envelope_signature(
    envelope: dict[str, Any],
    public_key_b64: str,
    errors: list[str],
) -> bool:
    if not _HAS_CRYPTOGRAPHY:
        errors.append("cryptography package not available — cannot verify Ed25519")
        return False
    try:
        public_bytes = base64.b64decode(public_key_b64)
        pk = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        sig_bytes = base64.b64decode(envelope.get("signature", ""))
        pk.verify(sig_bytes, _canonical_envelope_bytes(envelope))
        return True
    except Exception as exc:
        errors.append(f"signature verification failed: {exc}")
        return False


def _derive_summary(envelope: dict[str, Any]) -> dict[str, Any]:
    ts = envelope.get("timestamp")
    ts_iso: str | None = None
    if isinstance(ts, (int, float)):
        try:
            ts_iso = datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except (ValueError, OSError, OverflowError):
            ts_iso = None
    sig = str(envelope.get("signature") or "")
    return {
        "tool_id": envelope.get("tool_id"),
        "timestamp_iso": ts_iso,
        "signature_short": (sig[:8] + "…") if len(sig) > 8 else sig,
    }


__all__ = [
    "Receipt",
    "ReceiptError",
    "ReceiptFormatError",
    "ReceiptVerification",
    "ReceiptVerificationError",
    "RECEIPT_FORMAT",
    "RECEIPT_VERSION",
    "build_receipt",
    "verify_receipt",
]
