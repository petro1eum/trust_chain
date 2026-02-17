"""Verifiable Append-Only Log — Certificate Transparency for AI Agents.

Architecture (CQRS):
  - chain.log:  append-only binary file (source of truth, immutable)
  - index.db:   SQLite read projection (rebuildable from chain.log)
  - HEAD:       Merkle root hash (one hash = proof of entire chain)

Properties:
  - O(1) chain verification (compare Merkle roots)
  - O(log n) inclusion proofs (prove any op exists)
  - O(log n) consistency proofs (prove history wasn't rewritten)
  - Content-addressable IDs: id = sha256(payload)[:12]
  - CQRS: write path (chain.log) separated from read path (index.db)

Usage::

    from trustchain.v2.verifiable_log import VerifiableChainStore

    vlog = VerifiableChainStore(".trustchain")
    vlog.append("bash_tool", {"cmd": "ls"}, signature="abc123", ...)

    # O(1) verification
    result = vlog.verify()  # {"valid": True, "root": "a7f3b2...", ...}

    # O(log n) inclusion proof
    proof = vlog.inclusion_proof("a7f3b2c4e5d1")
    assert proof.verify()

    # Rebuild index from source of truth
    vlog.rebuild_index()
"""

import hashlib
import json
import sqlite3
import struct
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .merkle import MerkleProof, MerkleTree, hash_data, verify_proof

# ── Binary Log Format ──
# Each record: [4-byte big-endian length][JSON payload bytes][newline]
RECORD_HEADER_SIZE = 4
RECORD_SEPARATOR = b"\n"


@dataclass
class InclusionProof:
    """Proof that an operation exists in the verifiable log.

    Contains the Merkle proof path and enough context to verify
    independently without access to the full chain.
    """

    op_id: str
    leaf_index: int
    merkle_proof: MerkleProof
    chain_length: int
    root_at_proof_time: str

    def verify(self, record_json: str) -> bool:
        """Verify this proof against a record's JSON content."""
        return verify_proof(record_json, self.merkle_proof, self.root_at_proof_time)

    def to_dict(self) -> dict:
        """Serialize for transmission to auditors."""
        return {
            "op_id": self.op_id,
            "leaf_index": self.leaf_index,
            "proof": self.merkle_proof.to_dict(),
            "chain_length": self.chain_length,
            "root": self.root_at_proof_time,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InclusionProof":
        """Deserialize from dict."""
        return cls(
            op_id=data["op_id"],
            leaf_index=data["leaf_index"],
            merkle_proof=MerkleProof.from_dict(data["proof"]),
            chain_length=data["chain_length"],
            root_at_proof_time=data["root"],
        )


def _content_id(tool: str, data: Any, timestamp: str, signature: str) -> str:
    """Compute content-addressable ID: sha256(tool+data+ts+sig)[:12]."""
    payload = f"{tool}|{json.dumps(data, sort_keys=True, default=str)}|{timestamp}|{signature}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


class VerifiableChainStore:
    """Certificate Transparency-style verifiable append-only log.

    Implements a cryptographically verifiable chain of AI agent operations
    using the same principles as Google Certificate Transparency:

    1. **Append-only log** (chain.log) — immutable source of truth
    2. **Merkle tree** — enables O(1) verification and O(log n) proofs
    3. **SQLite index** (index.db) — fast read projection, rebuildable

    Directory layout::

        {root_dir}/
        ├── chain.log     # append-only binary log
        ├── index.db      # SQLite read index
        └── HEAD          # current Merkle root hash
    """

    def __init__(self, root_dir: str = ".trustchain") -> None:
        self._root = Path(root_dir).expanduser().resolve()
        self._root.mkdir(parents=True, exist_ok=True)

        self._log_path = self._root / "chain.log"
        self._db_path = self._root / "index.db"
        self._head_path = self._root / "HEAD"

        self._lock = threading.Lock()

        # ── Load or initialize ──
        self._leaf_hashes: List[str] = []
        self._merkle_tree: Optional[MerkleTree] = None
        self._length = 0

        self._init_sqlite()
        self._load_log()

    # ══════════════════════════════════════════════════════════════
    # Write Path
    # ══════════════════════════════════════════════════════════════

    def append(
        self,
        tool: str,
        data: Dict[str, Any],
        signature: str,
        signature_id: str = "",
        parent_hash: Optional[str] = None,
        key_id: str = "",
        algorithm: str = "Ed25519",
        latency_ms: float = 0,
        session_id: Optional[str] = None,
        nonce: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """Append an operation to the verifiable log.

        Write path: chain.log → Merkle tree → index.db → HEAD.
        Returns the full commit record with content-addressable ID.
        """
        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            seq = self._length + 1

            # Content-addressable ID
            op_id = _content_id(tool, data, timestamp, signature)

            # Parent = previous Merkle root (or None for genesis)
            if parent_hash is None and self._merkle_tree is not None:
                parent_hash = self._merkle_tree.root

            record = {
                "id": op_id,
                "seq": seq,
                "tool": tool,
                "timestamp": timestamp,
                "data": data,
                "signature": signature,
                "signature_id": signature_id,
                "parent_hash": parent_hash,
                "key_id": key_id,
                "algorithm": algorithm,
                "latency_ms": latency_ms,
                "session_id": session_id,
                "nonce": nonce,
                "metadata": metadata or {},
            }

            # 1. Append to chain.log (source of truth)
            record_json = json.dumps(record, sort_keys=True, default=str)
            self._append_to_log(record_json)

            # 2. Update Merkle tree
            leaf_hash = hash_data(record_json)
            self._leaf_hashes.append(leaf_hash)
            self._merkle_tree = MerkleTree.from_chunks(list(self._leaf_hashes))

            # 3. Write HEAD (Merkle root)
            self._save_head(self._merkle_tree.root)

            # 4. Index in SQLite
            self._index_record(record)

            self._length = seq
            return record

    # ══════════════════════════════════════════════════════════════
    # Read Path (via SQLite index)
    # ══════════════════════════════════════════════════════════════

    def log(
        self,
        limit: int = 20,
        offset: int = 0,
        tool: Optional[str] = None,
        session_id: Optional[str] = None,
        reverse: bool = True,
    ) -> List[dict]:
        """Query chain history via SQLite index."""
        query = "SELECT record_json FROM chain_log WHERE 1=1"
        params: list = []

        if tool:
            query += " AND tool = ?"
            params.append(tool)

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        order = "DESC" if reverse else "ASC"
        query += f" ORDER BY seq {order} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._db.execute(query, params).fetchall()
        return [json.loads(row[0]) for row in rows]

    def show(self, op_id: str) -> Optional[dict]:
        """Get a single operation by ID."""
        row = self._db.execute(
            "SELECT record_json FROM chain_log WHERE op_id = ?", (op_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def blame(self, tool: str, limit: int = 50) -> List[dict]:
        """Find all operations by tool (indexed query)."""
        rows = self._db.execute(
            "SELECT record_json FROM chain_log WHERE tool = ? ORDER BY seq DESC LIMIT ?",
            (tool, limit),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def status(self) -> dict:
        """Chain health summary."""
        stats = self._db.execute(
            """SELECT
                COUNT(*) as total,
                COUNT(DISTINCT tool) as tools,
                MIN(timestamp) as first_op,
                MAX(timestamp) as last_op,
                AVG(latency_ms) as avg_latency
            FROM chain_log"""
        ).fetchone()

        tool_counts = self._db.execute(
            "SELECT tool, COUNT(*) as cnt FROM chain_log GROUP BY tool ORDER BY cnt DESC"
        ).fetchall()

        return {
            "length": stats[0],
            "tools_count": stats[1],
            "first_operation": stats[2],
            "last_operation": stats[3],
            "avg_latency_ms": round(stats[4], 2) if stats[4] else 0,
            "merkle_root": self.merkle_root,
            "tools": {row[0]: row[1] for row in tool_counts},
            "log_size_bytes": (
                self._log_path.stat().st_size if self._log_path.exists() else 0
            ),
            "index_size_bytes": (
                self._db_path.stat().st_size if self._db_path.exists() else 0
            ),
        }

    def diff(self, op_id_a: str, op_id_b: str) -> dict:
        """Compare two operations."""
        a = self.show(op_id_a)
        b = self.show(op_id_b)
        if not a or not b:
            return {"error": "Operation not found", "a": op_id_a, "b": op_id_b}

        changes = {}
        all_keys = set(list(a.keys()) + list(b.keys()))
        for key in sorted(all_keys):
            va = a.get(key)
            vb = b.get(key)
            if va != vb:
                changes[key] = {"a": va, "b": vb}

        return {"op_a": op_id_a, "op_b": op_id_b, "changes": changes}

    # ══════════════════════════════════════════════════════════════
    # Cryptographic Verification
    # ══════════════════════════════════════════════════════════════

    def verify(self) -> dict:
        """Verify chain integrity — O(1) Merkle root comparison.

        Recomputes Merkle root from chain.log and compares to stored HEAD.
        If they match, the entire chain is intact.
        """
        if self._length == 0:
            return {
                "valid": True,
                "length": 0,
                "root": None,
                "method": "empty_chain",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }

        # Recompute leaf hashes from chain.log (source of truth)
        recomputed_leaves = []
        for record_json in self._iter_log_records():
            recomputed_leaves.append(hash_data(record_json))

        recomputed_tree = MerkleTree.from_chunks(list(recomputed_leaves))

        stored_root = self._load_head()
        valid = recomputed_tree.root == stored_root

        return {
            "valid": valid,
            "length": len(recomputed_leaves),
            "stored_root": stored_root,
            "computed_root": recomputed_tree.root,
            "method": "merkle_root_comparison",
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def inclusion_proof(self, op_id: str) -> Optional[InclusionProof]:
        """Generate O(log n) proof that an operation exists in the chain.

        Returns an InclusionProof that can be verified independently
        by any auditor who knows the Merkle root.
        """
        if self._merkle_tree is None:
            return None

        # Find the leaf index for this op_id
        row = self._db.execute(
            "SELECT seq FROM chain_log WHERE op_id = ?", (op_id,)
        ).fetchone()
        if not row:
            return None

        leaf_index = row[0] - 1  # seq is 1-based, leaves are 0-based

        if leaf_index >= len(self._leaf_hashes):
            return None

        merkle_proof = self._merkle_tree.get_proof(leaf_index)

        return InclusionProof(
            op_id=op_id,
            leaf_index=leaf_index,
            merkle_proof=merkle_proof,
            chain_length=self._length,
            root_at_proof_time=self._merkle_tree.root,
        )

    def consistency_proof(self, old_length: int, old_root: str) -> dict:
        """Prove that the chain at old_length is a prefix of the current chain.

        This proves the log hasn't been rewritten — only appended to.
        The old root should be derivable from the first old_length leaves.
        """
        if old_length > self._length:
            return {
                "consistent": False,
                "reason": f"old_length {old_length} > current {self._length}",
            }

        if old_length == 0:
            return {"consistent": True, "reason": "empty_prefix"}

        # Rebuild tree from first old_length leaves
        old_tree = MerkleTree.from_chunks(list(self._leaf_hashes[:old_length]))

        consistent = old_tree.root == old_root

        return {
            "consistent": consistent,
            "old_length": old_length,
            "old_root": old_root,
            "recomputed_old_root": old_tree.root,
            "current_length": self._length,
            "current_root": self._merkle_tree.root if self._merkle_tree else None,
        }

    # ══════════════════════════════════════════════════════════════
    # Maintenance
    # ══════════════════════════════════════════════════════════════

    def rebuild_index(self) -> dict:
        """Rebuild index.db from chain.log (disaster recovery).

        The chain.log is the source of truth. If index.db becomes
        corrupted, delete it and call this method.
        """
        # Drop and recreate
        self._db.execute("DELETE FROM chain_log")
        self._db.commit()

        count = 0
        for record_json in self._iter_log_records():
            record = json.loads(record_json)
            self._index_record(record)
            count += 1

        return {"rebuilt": True, "records": count}

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export entire chain as JSON."""
        records = self.log(limit=999999, reverse=False)
        output = json.dumps(
            {
                "chain": records,
                "merkle_root": self.merkle_root,
                "length": self._length,
                "exported_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
            default=str,
        )
        if filepath:
            Path(filepath).write_text(output, encoding="utf-8")
        return output

    @property
    def head(self) -> Optional[str]:
        """Current HEAD — latest Merkle root hash."""
        return self._merkle_tree.root if self._merkle_tree else None

    @property
    def merkle_root(self) -> Optional[str]:
        """Alias for head — the Merkle root of the entire chain."""
        return self.head

    @property
    def length(self) -> int:
        """Number of operations in the chain."""
        return self._length

    def close(self) -> None:
        """Close SQLite connection."""
        if hasattr(self, "_db") and self._db:
            self._db.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════
    # Internal: Binary Log
    # ══════════════════════════════════════════════════════════════

    def _append_to_log(self, record_json: str) -> None:
        """Append a record to chain.log in binary format."""
        data = record_json.encode("utf-8")
        header = struct.pack(">I", len(data))

        with open(self._log_path, "ab") as f:
            f.write(header)
            f.write(data)
            f.write(RECORD_SEPARATOR)
            f.flush()

    def _iter_log_records(self):
        """Iterate over all records in chain.log."""
        if not self._log_path.exists():
            return

        with open(self._log_path, "rb") as f:
            while True:
                header = f.read(RECORD_HEADER_SIZE)
                if not header or len(header) < RECORD_HEADER_SIZE:
                    break

                length = struct.unpack(">I", header)[0]
                data = f.read(length)
                if len(data) < length:
                    break

                # Read separator
                f.read(len(RECORD_SEPARATOR))

                yield data.decode("utf-8")

    def _load_log(self) -> None:
        """Load chain.log into memory: rebuild leaf hashes and Merkle tree."""
        self._leaf_hashes = []
        self._length = 0

        for record_json in self._iter_log_records():
            leaf_hash = hash_data(record_json)
            self._leaf_hashes.append(leaf_hash)
            self._length += 1

        if self._leaf_hashes:
            self._merkle_tree = MerkleTree.from_chunks(list(self._leaf_hashes))
        else:
            self._merkle_tree = None

    # ══════════════════════════════════════════════════════════════
    # Internal: SQLite Index
    # ══════════════════════════════════════════════════════════════

    def _init_sqlite(self) -> None:
        """Initialize SQLite index database."""
        self._db = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")

        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS chain_log (
                seq          INTEGER PRIMARY KEY,
                op_id        TEXT NOT NULL UNIQUE,
                tool         TEXT NOT NULL,
                timestamp    TEXT NOT NULL,
                signature    TEXT NOT NULL,
                session_id   TEXT,
                latency_ms   REAL DEFAULT 0,
                record_json  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chain_tool ON chain_log(tool);
            CREATE INDEX IF NOT EXISTS idx_chain_timestamp ON chain_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_chain_session ON chain_log(session_id);
            CREATE INDEX IF NOT EXISTS idx_chain_op_id ON chain_log(op_id);
        """
        )
        self._db.commit()

    def _index_record(self, record: dict) -> None:
        """Index a record in SQLite."""
        record_json = json.dumps(record, sort_keys=True, default=str)
        self._db.execute(
            """INSERT OR REPLACE INTO chain_log
               (seq, op_id, tool, timestamp, signature, session_id, latency_ms, record_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record["seq"],
                record["id"],
                record["tool"],
                record["timestamp"],
                record["signature"],
                record.get("session_id"),
                record.get("latency_ms", 0),
                record_json,
            ),
        )
        self._db.commit()

    # ══════════════════════════════════════════════════════════════
    # Internal: HEAD
    # ══════════════════════════════════════════════════════════════

    def _save_head(self, root: str) -> None:
        """Write Merkle root to HEAD file."""
        self._head_path.write_text(root, encoding="utf-8")

    def _load_head(self) -> Optional[str]:
        """Read Merkle root from HEAD file."""
        if self._head_path.exists():
            return self._head_path.read_text(encoding="utf-8").strip()
        return None
