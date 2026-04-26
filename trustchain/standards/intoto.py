"""in-toto Statement adapter for TrustChain receipts.

The output is a normal in-toto Statement v1.0 with a TrustChain predicate. It
can be signed by DSSE/cosign externally; TrustChain does not need to own that
signing layer to expose its evidence in supply-chain tooling.
"""

from __future__ import annotations

from typing import Any

from trustchain.receipt import Receipt
from trustchain.v2.signer import SignedResponse

from ._common import as_envelope, envelope_tool_id, sha256_hex

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
TRUSTCHAIN_PREDICATE_TYPE = "https://trust-chain.ai/predicate/tcreceipt/v1"


def to_intoto_statement(
    source: Receipt | SignedResponse | dict[str, Any],
    *,
    subject_name: str | None = None,
) -> dict[str, Any]:
    """Export a TrustChain signed response as an in-toto Statement."""
    envelope = as_envelope(source)
    envelope_hash = sha256_hex(envelope)
    name = subject_name or f"trustchain:tool:{envelope_tool_id(envelope)}"

    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": name,
                "digest": {
                    "sha256": envelope_hash,
                },
            }
        ],
        "predicateType": TRUSTCHAIN_PREDICATE_TYPE,
        "predicate": {
            "tool_id": envelope_tool_id(envelope),
            "signature": envelope.get("signature"),
            "signature_id": envelope.get("signature_id"),
            "parent_signature": envelope.get("parent_signature"),
            "timestamp": envelope.get("timestamp"),
            "trustchain_envelope": envelope,
        },
    }


def verify_intoto_statement_shape(statement: dict[str, Any]) -> bool:
    """Check that a TrustChain in-toto Statement matches its subject digest."""
    try:
        if statement.get("_type") != INTOTO_STATEMENT_TYPE:
            return False
        if statement.get("predicateType") != TRUSTCHAIN_PREDICATE_TYPE:
            return False
        envelope = statement["predicate"]["trustchain_envelope"]
        expected = statement["subject"][0]["digest"]["sha256"]
        return expected == sha256_hex(envelope)
    except (KeyError, IndexError, TypeError):
        return False


__all__ = [
    "INTOTO_STATEMENT_TYPE",
    "TRUSTCHAIN_PREDICATE_TYPE",
    "to_intoto_statement",
    "verify_intoto_statement_shape",
]
