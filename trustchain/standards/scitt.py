"""SCITT-oriented JSON profile for TrustChain execution evidence.

SCITT itself uses COSE and a transparency service. This module does not pretend
to issue a SCITT Evidence Receipt. It produces a deterministic AIR-shaped JSON
record that carries the same core integrity fields, so an operator can later
wrap it in COSE_Sign1 or submit it to a SCITT transparency service.
"""

from __future__ import annotations

from typing import Any

from trustchain.receipt import Receipt
from trustchain.v2.signer import SignedResponse

from ._common import (
    TRUSTCHAIN_CANONICALIZATION,
    as_envelope,
    envelope_timestamp_ms,
    envelope_tool_id,
    sha256_hex,
)

SCITT_AIR_JSON_PROFILE = "trustchain.scitt.air-json.v1"
SCITT_AIR_PAYLOAD_TYPE = "application/vnd.trustchain.scitt.air+json;version=1"


def to_scitt_air_json(
    source: Receipt | SignedResponse | dict[str, Any],
    *,
    agent_id: str,
    sequence_number: int,
    previous_chain_hash: str | None = None,
) -> dict[str, Any]:
    """Export TrustChain evidence as an AIR-shaped SCITT JSON profile.

    The returned document is deterministic and self-describing, but it is not a
    COSE_Sign1 envelope and it is not an admission receipt from a transparency
    service. Enterprise custody can wrap this JSON profile without changing the
    native TrustChain receipt.
    """
    if sequence_number < 0:
        raise ValueError("sequence_number must be >= 0")

    envelope = as_envelope(source)
    content_hash = sha256_hex(envelope)
    action_timestamp_ms = envelope_timestamp_ms(envelope)
    chain_material = {
        "agent_id": agent_id,
        "content_hash": content_hash,
        "prev_chain_hash": previous_chain_hash,
        "sequence_number": sequence_number,
        "action_timestamp_ms": action_timestamp_ms,
    }
    chain_hash = sha256_hex(chain_material)

    return {
        "profile": SCITT_AIR_JSON_PROFILE,
        "protected_headers": {
            "content_type": SCITT_AIR_PAYLOAD_TYPE,
            "content_hash_alg": "sha256",
            "content_hash": content_hash,
            "prev_chain_hash": previous_chain_hash,
            "chain_hash": chain_hash,
            "sequence_number": sequence_number,
            "action_timestamp_ms": action_timestamp_ms,
            "agent_id": agent_id,
        },
        "payload": {
            "record_type": "AgentInteractionRecord",
            "tool_id": envelope_tool_id(envelope),
            "signed_response": envelope,
            "trustchain_signature": envelope.get("signature"),
            "trustchain_signature_id": envelope.get("signature_id"),
            "canonicalization": TRUSTCHAIN_CANONICALIZATION,
        },
    }


def verify_scitt_air_json(record: dict[str, Any]) -> bool:
    """Verify deterministic integrity fields of the SCITT JSON profile."""
    try:
        if record.get("profile") != SCITT_AIR_JSON_PROFILE:
            return False
        headers = record["protected_headers"]
        payload = record["payload"]
        envelope = payload["signed_response"]

        content_hash = sha256_hex(envelope)
        if headers.get("content_hash") != content_hash:
            return False

        chain_material = {
            "agent_id": headers.get("agent_id"),
            "content_hash": content_hash,
            "prev_chain_hash": headers.get("prev_chain_hash"),
            "sequence_number": headers.get("sequence_number"),
            "action_timestamp_ms": headers.get("action_timestamp_ms"),
        }
        return headers.get("chain_hash") == sha256_hex(chain_material)
    except (KeyError, TypeError):
        return False


__all__ = [
    "SCITT_AIR_JSON_PROFILE",
    "SCITT_AIR_PAYLOAD_TYPE",
    "to_scitt_air_json",
    "verify_scitt_air_json",
]
