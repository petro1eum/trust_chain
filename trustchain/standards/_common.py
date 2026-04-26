"""Shared helpers for standards-oriented TrustChain adapters.

The adapters in this package intentionally avoid claiming full compliance with
standards that require external services or binary envelopes. They provide
deterministic JSON profiles that can be handed to SCITT, W3C VC, in-toto, or
Sigstore tooling without changing the native TrustChain receipt format.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from trustchain.receipt import Receipt
from trustchain.v2.signer import SignedResponse

TRUSTCHAIN_CANONICALIZATION = "json-sort-keys-minified"


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic JSON bytes used by the standards adapters."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """Return SHA-256 hex over deterministic JSON bytes."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def as_receipt_dict(source: Receipt | dict[str, Any]) -> dict[str, Any]:
    """Normalize a Receipt-like object to its public dict representation."""
    if isinstance(source, Receipt):
        return source.to_dict()
    if isinstance(source, dict) and source.get("format") == "tcreceipt":
        return dict(source)
    raise TypeError("Expected a TrustChain Receipt or .tcreceipt dict")


def as_envelope(source: Receipt | SignedResponse | dict[str, Any]) -> dict[str, Any]:
    """Extract a signed response envelope from supported TrustChain objects."""
    if isinstance(source, Receipt):
        return dict(source.envelope)
    if isinstance(source, SignedResponse):
        return source.to_dict()
    if isinstance(source, dict):
        if source.get("format") == "tcreceipt":
            envelope = source.get("envelope")
            if isinstance(envelope, dict):
                return dict(envelope)
        if isinstance(source.get("envelope"), dict):
            return dict(source["envelope"])
        if "tool_id" in source and "signature" in source:
            return dict(source)
    raise TypeError(
        "Expected Receipt, SignedResponse, .tcreceipt dict, or envelope dict"
    )


def envelope_timestamp_ms(envelope: dict[str, Any]) -> int | None:
    """Convert a TrustChain floating timestamp to milliseconds when present."""
    ts = envelope.get("timestamp")
    if isinstance(ts, (int, float)):
        return int(float(ts) * 1000)
    return None


def envelope_tool_id(envelope: dict[str, Any]) -> str:
    """Return a stable tool/action identifier for adapter payloads."""
    return str(envelope.get("tool_id") or "unknown")


__all__ = [
    "TRUSTCHAIN_CANONICALIZATION",
    "as_envelope",
    "as_receipt_dict",
    "canonical_json_bytes",
    "envelope_timestamp_ms",
    "envelope_tool_id",
    "sha256_hex",
]
