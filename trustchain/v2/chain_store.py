"""ChainStore — Git-like persistent chain-of-trust ledger.

Provides a high-level API for managing a cryptographic chain of signed
operations, using Git-like semantics: commits, HEAD, refs, log, blame.

The chain is stored in a .trustchain/ directory structure:

    .trustchain/
    ├── HEAD                  # latest commit signature
    ├── config.json           # chain metadata
    ├── objects/              # one JSON file per signed operation
    │   ├── op_0001.json
    │   └── ...
    └── refs/
        └── sessions/         # per-session HEAD pointers
            ├── task_abc123
            └── task_def456

Usage:
    from trustchain import TrustChain
    tc = TrustChain(config=TrustChainConfig(chain_storage="file"))

    # Signing automatically appends to chain
    signed = tc.sign("bash_tool", {"command": "ls -la"})

    # Query the chain
    tc.chain.log(limit=10)           # like `git log`
    tc.chain.verify()                # like `git verify-commit`
    tc.chain.head()                  # current HEAD
    tc.chain.blame("bash_tool")      # find operations by tool
    tc.chain.status()                # chain health summary
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .storage import Storage


class ChainStore:
    """Git-like persistent chain-of-trust ledger.

    Wraps a Storage backend with chain-specific semantics:
    - Ordered append-only ledger (each commit links to parent)
    - HEAD tracking (latest commit signature)
    - Session refs (per-session HEAD pointers)
    - Log, blame, verify operations
    """

    def __init__(self, storage: Storage, root_dir: Optional[str] = None):
        self._storage = storage
        self._root = Path(root_dir).expanduser().resolve() if root_dir else None
        self._length = 0
        self._head: Optional[str] = None  # latest signature
        self._last_parent_sig: Optional[str] = None

        # Initialize from persisted state
        self._load_state()

    # ── Git-like public API ──

    def commit(
        self,
        tool: str,
        data: Dict[str, Any],
        signature: str,
        signature_id: str,
        nonce: Optional[str] = None,
        parent_signature: Optional[str] = None,
        key_id: str = "",
        algorithm: str = "Ed25519",
        latency_ms: float = 0,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a signed operation to the chain (like `git commit`).

        Returns the full commit record.
        """
        self._length += 1
        op_id = f"op_{self._length:04d}"

        record = {
            "id": op_id,
            "tool": tool,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
            "latency_ms": latency_ms,
            "signature": signature,
            "signature_id": signature_id,
            "nonce": nonce,
            "parent_signature": parent_signature,
            "key_id": key_id,
            "algorithm": algorithm,
        }
        if metadata:
            record["metadata"] = metadata

        # Store the object
        self._storage.store(op_id, record)

        # Update HEAD
        self._head = signature
        self._last_parent_sig = signature
        self._save_head()

        # Update session ref if provided
        if session_id:
            self._save_ref(session_id, signature)

        return record

    def head(self) -> Optional[str]:
        """Get current HEAD signature (like `git rev-parse HEAD`)."""
        return self._head

    def parent_signature(self) -> Optional[str]:
        """Get the parent signature for the next commit."""
        return self._last_parent_sig

    def log(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Return chain history (like `git log`).

        Returns operations in chronological order (oldest first).
        """
        all_ops = self._storage.list_all()
        # Sort by id to ensure order
        all_ops.sort(key=lambda x: x.get("id", "") if isinstance(x, dict) else "")
        return all_ops[offset : offset + limit]

    def log_reverse(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return chain history newest-first (like `git log` default)."""
        all_ops = self._storage.list_all()
        all_ops.sort(
            key=lambda x: x.get("id", "") if isinstance(x, dict) else "", reverse=True
        )
        return all_ops[:limit]

    def show(self, op_id: str) -> Optional[Dict[str, Any]]:
        """Show a single commit (like `git show <hash>`)."""
        return self._storage.get(op_id)

    def blame(self, tool: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Find all operations by a specific tool (like `git blame`).

        Useful for forensic investigation: "show me every time
        the agent ran bash_tool".
        """
        all_ops = self._storage.list_all()
        results = [
            op for op in all_ops if isinstance(op, dict) and op.get("tool") == tool
        ]
        return results[:limit]

    def verify(self) -> Dict[str, Any]:
        """Verify the integrity of the entire chain (like `git fsck`).

        Checks that each operation's parent_signature matches the
        previous operation's signature — ensuring no tampering,
        insertion, or deletion of records.

        Returns:
            {
                "valid": bool,
                "length": int,
                "head": str | None,
                "broken_links": [...],
                "verified_at": str
            }
        """
        all_ops = self.log(limit=999999)
        broken = []

        if not all_ops:
            return {
                "valid": True,
                "length": 0,
                "head": None,
                "broken_links": [],
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }

        # First operation should have no parent (or None)
        for i in range(1, len(all_ops)):
            prev_sig = all_ops[i - 1].get("signature")
            this_parent = all_ops[i].get("parent_signature")
            if this_parent != prev_sig:
                broken.append(
                    {
                        "index": i,
                        "id": all_ops[i].get("id"),
                        "expected_parent": prev_sig,
                        "actual_parent": this_parent,
                    }
                )

        return {
            "valid": len(broken) == 0,
            "length": len(all_ops),
            "head": all_ops[-1].get("signature") if all_ops else None,
            "broken_links": broken,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def status(self) -> Dict[str, Any]:
        """Chain health summary (like `git status`).

        Returns overall stats: length, tools used, latest commit, etc.
        """
        all_ops = self._storage.list_all()
        tools_count: Dict[str, int] = {}
        total_latency = 0.0

        for op in all_ops:
            if isinstance(op, dict):
                tool = op.get("tool", "unknown")
                tools_count[tool] = tools_count.get(tool, 0) + 1
                total_latency += op.get("latency_ms", 0)

        total = len(all_ops)
        return {
            "length": total,
            "head": self._head,
            "tools": tools_count,
            "avg_latency_ms": round(total_latency / total, 2) if total > 0 else 0,
            "storage_backend": type(self._storage).__name__,
            "root_dir": str(self._root) if self._root else None,
        }

    def diff(self, op_id_a: str, op_id_b: str) -> Dict[str, Any]:
        """Compare two operations (like `git diff`)."""
        a = self.show(op_id_a)
        b = self.show(op_id_b)
        if not a or not b:
            return {"error": "One or both operations not found"}

        return {
            "a": {"id": op_id_a, "tool": a.get("tool"), "data": a.get("data")},
            "b": {"id": op_id_b, "tool": b.get("tool"), "data": b.get("data")},
            "same_tool": a.get("tool") == b.get("tool"),
            "time_delta_seconds": self._time_delta(a, b),
        }

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export entire chain as JSON."""
        data = {
            "head": self._head,
            "status": self.status(),
            "chain": self.log(limit=999999),
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }
        json_str = json.dumps(data, indent=2, default=str)
        if filepath:
            Path(filepath).write_text(json_str, encoding="utf-8")
        return json_str

    # ── Session refs ──

    def sessions(self) -> List[str]:
        """List all session refs (like `git branch -a`)."""
        if not self._root:
            return []
        refs_dir = self._root / "refs" / "sessions"
        if not refs_dir.exists():
            return []
        return sorted(f.stem for f in refs_dir.glob("*.ref"))

    def session_head(self, session_id: str) -> Optional[str]:
        """Get HEAD for a specific session (like `git rev-parse <branch>`)."""
        if not self._root:
            return None
        ref_path = self._root / "refs" / "sessions" / f"{session_id}.ref"
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip()
        return None

    # ── Properties ──

    @property
    def length(self) -> int:
        """Number of operations in the chain."""
        return self._length

    # ── Internal ──

    def _load_state(self) -> None:
        """Load HEAD and chain length from persisted state."""
        if self._root:
            head_path = self._root / "HEAD"
            if head_path.exists():
                self._head = head_path.read_text(encoding="utf-8").strip()
                self._last_parent_sig = self._head

        # Count existing objects
        all_ops = self._storage.list_all()
        self._length = len(all_ops)

        # If we have operations but no HEAD from file, derive from last op
        if all_ops and not self._head:
            sorted_ops = sorted(
                all_ops, key=lambda x: x.get("id", "") if isinstance(x, dict) else ""
            )
            if sorted_ops:
                last = sorted_ops[-1]
                if isinstance(last, dict):
                    self._head = last.get("signature")
                    self._last_parent_sig = self._head

    def _save_head(self) -> None:
        """Persist HEAD to file."""
        if self._root and self._head:
            head_path = self._root / "HEAD"
            head_path.write_text(self._head, encoding="utf-8")

    def _save_ref(self, session_id: str, signature: str) -> None:
        """Persist a session ref."""
        if self._root:
            refs_dir = self._root / "refs" / "sessions"
            refs_dir.mkdir(parents=True, exist_ok=True)
            safe_id = session_id.replace("/", "_").replace("\\", "_")
            ref_path = refs_dir / f"{safe_id}.ref"
            ref_path.write_text(signature, encoding="utf-8")

    @staticmethod
    def _time_delta(a: dict, b: dict) -> Optional[float]:
        """Calculate time delta between two operations."""
        try:
            t_a = datetime.fromisoformat(a["timestamp"])
            t_b = datetime.fromisoformat(b["timestamp"])
            return abs((t_b - t_a).total_seconds())
        except (KeyError, ValueError):
            return None
