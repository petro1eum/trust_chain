"""Linear v2 chain → v3 CAS commits (one Commit per v2 operation)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trustchain.v2.chain_store import ChainStore
from trustchain.v2.storage import FileStorage
from trustchain.v3.objects import Blob, Commit, Ref, _canon_json, _sha256_hex


def _v2_op_blob_record(op: dict[str, Any]) -> dict[str, Any]:
    """Stable subset of a v2 operation for content-addressed blob."""
    keys = (
        "id",
        "tool",
        "timestamp",
        "signature",
        "signature_id",
        "parent_signature",
        "key_id",
        "algorithm",
        "latency_ms",
        "nonce",
        "data",
        "metadata",
    )
    return {k: op[k] for k in keys if k in op}


def migrate_v2_linear_to_v3(
    chain_root: Path,
    *,
    apply: bool,
    max_ops: int = 500_000,
) -> tuple[dict[str, Any], list[str]]:
    """Build v3 Commit chain mirroring linear v2 ``parent_signature`` order.

    Returns ``(report_dict, warnings)``. With ``apply=False`` only counts and
    tip digest preview; no files under ``objects/`` (CAS) or ``v3/`` are written.

    Raises ``ValueError`` if chain uses verifiable backend.
    """
    chain_root = chain_root.expanduser().resolve()
    storage = FileStorage(str(chain_root))
    chain = ChainStore(storage, root_dir=str(chain_root))
    if getattr(chain, "_vlog", None):
        raise ValueError("migrate-v3 supports file ChainStore only (no verifiable log)")

    ops: list[dict[str, Any]] = [
        o for o in chain.log(limit=max_ops, offset=0) if isinstance(o, dict)
    ]
    warnings: list[str] = []
    if len(ops) >= max_ops:
        warnings.append(f"truncated at max_ops={max_ops}")

    if not ops:
        return (
            {
                "v2_ops": 0,
                "commits": 0,
                "tip_commit": None,
                "apply": apply,
            },
            warnings,
        )

    prev_commit_digest: str | None = None
    tip: str | None = None
    mapping: dict[str, str] = {}

    for op in ops:
        payload = _v2_op_blob_record(op)
        op_blob = Blob(_canon_json(payload).encode("utf-8"))
        tree_body = {"type": "tree", "entries": {"v2_op": op_blob.digest}}
        tree_digest = _sha256_hex(_canon_json(tree_body).encode("utf-8"))
        parents = [prev_commit_digest] if prev_commit_digest else []
        op_id = str(op.get("id", "?"))
        tool = str(op.get("tool", "?"))
        meta = {
            "v2_op_id": op_id,
            "migrated_from": "v2_linear",
            "schema": "migrate-v3/1",
        }
        commit = Commit(
            tree_digest=tree_digest,
            parents=parents,
            message=f"{tool}: {op_id}",
            metadata=meta,
        )
        tip = commit.digest
        mapping[op_id] = tip

        if apply:
            op_blob.write(chain_root)
            Blob(_canon_json(tree_body).encode("utf-8")).write(chain_root)
            commit.write(chain_root)

        prev_commit_digest = tip

    assert tip is not None
    report: dict[str, Any] = {
        "v2_ops": len(ops),
        "commits": len(ops),
        "tip_commit": tip,
        "tip_preview": tip[:16] + "…",
        "apply": apply,
    }

    if apply:
        v3dir = chain_root / "v3"
        v3dir.mkdir(parents=True, exist_ok=True)
        state = {
            "version": 1,
            "schema": "migrate-v3/1",
            "source_v2_ops": len(ops),
            "tip_commit": tip,
            "migrated_at": datetime.now(timezone.utc).isoformat(),
            "op_id_to_commit": mapping,
        }
        (v3dir / "migration_state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        Ref(name="v3/main", commit_digest=tip).write(chain_root)

    return report, warnings


def migration_state_path(chain_root: Path) -> Path:
    return chain_root.expanduser().resolve() / "v3" / "migration_state.json"
