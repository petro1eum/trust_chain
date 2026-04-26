"""W3C Verifiable Credential envelope for native TrustChain receipts.

The native TrustChain signature remains the source of truth. This adapter wraps
a ``.tcreceipt`` in a VC-shaped JSON object for ecosystems that expect VC-like
issuers, subjects, proof metadata, and status hooks.
"""

from __future__ import annotations

from typing import Any

from trustchain.receipt import Receipt

from ._common import as_receipt_dict, sha256_hex

VC_CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://trust-chain.ai/contexts/tcreceipt/v1",
]
VC_TYPE = ["VerifiableCredential", "TrustChainReceiptCredential"]
VC_PROOF_TYPE = "TrustChainReceiptProof2026"


def to_w3c_vc(
    source: Receipt | dict[str, Any],
    *,
    issuer: str,
    subject_id: str,
    credential_id: str | None = None,
) -> dict[str, Any]:
    """Wrap a native ``.tcreceipt`` as a VC-shaped credential."""
    receipt = as_receipt_dict(source)
    receipt_hash = sha256_hex(receipt)
    issued_at = str(receipt.get("issued_at") or "")
    envelope = receipt.get("envelope") or {}
    key = receipt.get("key") or {}

    return {
        "@context": VC_CONTEXT,
        "id": credential_id or f"urn:trustchain:receipt:{receipt_hash}",
        "type": VC_TYPE,
        "issuer": issuer,
        "validFrom": issued_at,
        "credentialSubject": {
            "id": subject_id,
            "type": "TrustChainSignedToolOutput",
            "toolId": envelope.get("tool_id"),
            "signatureId": envelope.get("signature_id"),
            "receiptHash": f"sha256:{receipt_hash}",
            "receipt": receipt,
        },
        "proof": {
            "type": VC_PROOF_TYPE,
            "cryptosuite": "ed25519-trustchain-receipt-v1",
            "created": issued_at,
            "proofPurpose": "assertionMethod",
            "verificationMethod": key.get("key_id") or issuer,
            "proofValue": envelope.get("signature"),
            "proofHash": f"sha256:{sha256_hex(envelope)}",
            "proofScope": "native TrustChain envelope, not the surrounding VC JSON",
        },
    }


def receipt_from_w3c_vc(vc: dict[str, Any]) -> dict[str, Any]:
    """Extract the embedded native receipt from a TrustChain VC envelope."""
    try:
        subject = vc["credentialSubject"]
        receipt = subject["receipt"]
    except (KeyError, TypeError) as exc:
        raise ValueError("VC does not contain a TrustChain receipt") from exc

    return as_receipt_dict(receipt)


def verify_w3c_vc_shape(vc: dict[str, Any]) -> bool:
    """Check that the VC envelope is internally consistent."""
    try:
        receipt = receipt_from_w3c_vc(vc)
        receipt_hash = sha256_hex(receipt)
        subject = vc["credentialSubject"]
        proof = vc["proof"]
        envelope = receipt["envelope"]
        return (
            subject.get("receiptHash") == f"sha256:{receipt_hash}"
            and subject.get("toolId") == envelope.get("tool_id")
            and proof.get("proofHash") == f"sha256:{sha256_hex(envelope)}"
            and proof.get("proofValue") == envelope.get("signature")
        )
    except (KeyError, TypeError, ValueError):
        return False


__all__ = [
    "VC_CONTEXT",
    "VC_PROOF_TYPE",
    "VC_TYPE",
    "receipt_from_w3c_vc",
    "to_w3c_vc",
    "verify_w3c_vc_shape",
]
