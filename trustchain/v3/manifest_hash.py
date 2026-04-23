"""Canonical SHA-256 for tool/skill manifest JSON (tc.manifestHash)."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_manifest_json(manifest: dict[str, Any]) -> str:
    """UTF-8 JSON with sorted keys and minimal separators (matches CAS tooling)."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), default=str)


def tool_manifest_sha256_hex(manifest: dict[str, Any]) -> str:
    """Return lowercase hex SHA-256 of canonical manifest bytes."""
    raw = canonical_manifest_json(manifest).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
