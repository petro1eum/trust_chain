"""Compensating tool pairs for ``revert`` / rollback (v3 context layer).

Libraries and hosts register ``(forward_tool_id, reverse_tool_id)`` so a policy
engine or future ``tc revert`` can resolve the compensating call. This module
does **not** execute tools — it is a small registry + helpers only.
"""

from __future__ import annotations

import json
from pathlib import Path

_TOOL_PAIRS: dict[str, str] = {}


def register_reversible(forward_tool: str, reverse_tool: str) -> None:
    """Map a forward tool name to its compensating reverse tool name."""
    ft = forward_tool.strip()
    rt = reverse_tool.strip()
    if not ft or not rt:
        raise ValueError("forward_tool and reverse_tool must be non-empty")
    _TOOL_PAIRS[ft] = rt


def reverse_tool_for(forward_tool: str) -> str | None:
    """Return registered reverse tool id, or ``None``."""
    return _TOOL_PAIRS.get(forward_tool.strip())


def reverse_tool_for_chain(chain_root: Path, forward_tool: str) -> str | None:
    """Process registry first, then optional ``.trustchain/reversibles.json`` map.

    JSON shape: ``{\"forward_tool_id\": \"reverse_tool_id\", ...}`` so ``tc revert``
    works in a fresh CLI process without prior ``register_reversible`` calls.
    """
    ft = forward_tool.strip()
    hit = reverse_tool_for(ft)
    if hit:
        return hit
    path = chain_root / "reversibles.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    v = data.get(ft)
    return str(v).strip() if isinstance(v, str) and v.strip() else None


def clear_registry() -> None:
    """Test helper — reset all registrations."""
    _TOOL_PAIRS.clear()
