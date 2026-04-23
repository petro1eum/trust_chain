"""Walk linear v3 commit chain from ``refs/v3/main``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from trustchain.v3.cas_io import read_cas_json


def v3_commits_newest_first(
    trustchain_root: Path, *, limit: int = 100
) -> list[dict[str, Any]]:
    """Load up to ``limit`` commits starting at ``refs/v3/main``, newest first.

    Each row is shaped like a v2 op dict for reuse of ``tc log`` / ``_graph_prefixes``:
    ``id``, ``tool``, ``signature`` (commit digest), ``parent_signature`` (first parent),
    ``timestamp``, ``_v3_message``, ``_v3_metadata``.
    """
    ref = trustchain_root / "refs" / "v3" / "main"
    if not ref.is_file():
        return []
    tip = ref.read_text(encoding="utf-8").strip()
    if not tip:
        return []

    rows: list[dict[str, Any]] = []
    cur: str | None = tip
    while cur and len(rows) < limit:
        obj = read_cas_json(trustchain_root, cur)
        if not isinstance(obj, dict) or obj.get("type") != "commit":
            break
        meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
        msg = str(obj.get("message") or "")
        tool = "?"
        op_id = str(meta.get("v2_op_id") or cur[:16])
        if ":" in msg:
            tool, _, rest = msg.partition(":")
            op_id = rest.strip() or op_id
        parents = obj.get("parents")
        if not isinstance(parents, list):
            parents = []
        parent_sig = str(parents[0]) if parents else ""

        rows.append(
            {
                "id": op_id,
                "tool": tool.strip() or "?",
                "signature": cur,
                "parent_signature": parent_sig,
                "timestamp": "",
                "latency_ms": 0,
                "data": {},
                "_v3_message": msg,
                "_v3_metadata": meta,
            }
        )
        cur = parent_sig if parent_sig else None

    return rows
