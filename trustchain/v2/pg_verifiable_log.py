"""PostgresVerifiableChainStore — Certificate Transparency-style log on PostgreSQL.

v3 canonical backend for :class:`trustchain.v2.chain_store.ChainStore`.  Keeps
the same public contract as the legacy :class:`VerifiableChainStore`
(``append``, ``log``, ``verify``, ``inclusion_proof``, ``consistency_proof``,
``status`` …), but persists everything in a PostgreSQL schema instead of a
local ``chain.log`` / ``index.db`` / ``HEAD`` triple.

Schema (``tc_verifiable_log`` by default, see ADR-SEC-002 / ADR-SEC-005)::

    chain_records (append-only, enforced by triggers)
      seq          BIGSERIAL PRIMARY KEY
      op_id        TEXT UNIQUE NOT NULL         -- sha256 hex, content-addressable
      tool         TEXT NOT NULL
      ts           TIMESTAMPTZ NOT NULL DEFAULT now()
      signature    TEXT NOT NULL
      session_id   TEXT
      latency_ms   DOUBLE PRECISION NOT NULL DEFAULT 0
      leaf_hash    TEXT NOT NULL                -- sha256(record_json)
      record_json  TEXT NOT NULL                -- canonical JSON, source of truth

    chain_head (single row)
      id           TEXT PRIMARY KEY             -- always 'HEAD'
      merkle_root  TEXT NOT NULL
      length       BIGINT NOT NULL
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()

Cryptographic properties:

* ``record_json`` stored verbatim — ``verify()`` recomputes the Merkle root by
  hashing rows in ``seq`` order, no JSONB normalisation drift.
* ``UPDATE`` / ``DELETE`` / ``TRUNCATE`` on ``chain_records`` raise via
  ``BEFORE`` triggers — the table is strictly append-only.
* Append uses ``pg_advisory_xact_lock`` so multiple Python workers writing to
  the same chain still produce a deterministic Merkle tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    import psycopg
    from psycopg_pool import ConnectionPool
except ImportError as exc:  # pragma: no cover — dep is declared in pyproject.toml
    raise ImportError(
        "PostgresVerifiableChainStore requires psycopg[binary,pool]; "
        "install trustchain[postgres] or add it to your project dependencies."
    ) from exc

from .merkle import MerkleProof, MerkleTree, hash_data, verify_proof


# ── Advisory-lock key: статический 64-битный идентификатор (одна схема — одна
#    цепь).  Если в будущем появятся шардированные chains, можно добавить
#    вторую координату через pg_advisory_xact_lock(key1, key2).
#    0x7C23A1004C067C23 = "tc a1oo4c o6 tc23" — читаемо в pg_locks.
_ADVISORY_LOCK_KEY = 0x7C23A1004C067C23


@dataclass
class InclusionProof:
    """Proof that an operation exists in the verifiable log."""

    op_id: str
    leaf_index: int
    merkle_proof: MerkleProof
    chain_length: int
    root_at_proof_time: str

    def verify(self, record_json: str) -> bool:
        return verify_proof(record_json, self.merkle_proof, self.root_at_proof_time)

    def to_dict(self) -> dict:
        return {
            "op_id": self.op_id,
            "leaf_index": self.leaf_index,
            "proof": self.merkle_proof.to_dict(),
            "chain_length": self.chain_length,
            "root": self.root_at_proof_time,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InclusionProof":
        return cls(
            op_id=data["op_id"],
            leaf_index=data["leaf_index"],
            merkle_proof=MerkleProof.from_dict(data["proof"]),
            chain_length=data["chain_length"],
            root_at_proof_time=data["root"],
        )


def _content_id(tool: str, data: Any, timestamp: str, signature: str) -> str:
    """Content-addressable op_id — sha256 hex."""
    payload = f"{tool}|{json.dumps(data, sort_keys=True, default=str)}|{timestamp}|{signature}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── DDL (идемпотентный) ──────────────────────────────────────────────────────
_DDL = """
CREATE TABLE IF NOT EXISTS chain_records (
    seq         BIGSERIAL PRIMARY KEY,
    op_id       TEXT NOT NULL UNIQUE,
    tool        TEXT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    signature   TEXT NOT NULL,
    session_id  TEXT,
    latency_ms  DOUBLE PRECISION NOT NULL DEFAULT 0,
    leaf_hash   TEXT NOT NULL,
    record_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chain_tool    ON chain_records(tool);
CREATE INDEX IF NOT EXISTS idx_chain_ts      ON chain_records(ts);
CREATE INDEX IF NOT EXISTS idx_chain_session ON chain_records(session_id);

CREATE TABLE IF NOT EXISTS chain_head (
    id          TEXT PRIMARY KEY CHECK (id = 'HEAD'),
    merkle_root TEXT NOT NULL,
    length      BIGINT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION chain_records_deny_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'chain_records is append-only (ADR-SEC-005)';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'chain_records_no_mutation'
    ) THEN
        CREATE TRIGGER chain_records_no_mutation
        BEFORE UPDATE OR DELETE ON chain_records
        FOR EACH ROW EXECUTE FUNCTION chain_records_deny_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'chain_records_no_truncate'
    ) THEN
        CREATE TRIGGER chain_records_no_truncate
        BEFORE TRUNCATE ON chain_records
        FOR EACH STATEMENT EXECUTE FUNCTION chain_records_deny_mutation();
    END IF;
END
$$;
"""


class PostgresVerifiableChainStore:
    """PostgreSQL-backed append-only verifiable log.

    Parameters
    ----------
    dsn : optional DSN override.  Defaults to ``$TC_VERIFIABLE_LOG_DSN``; if
        neither is provided a ``RuntimeError`` is raised (fail-closed, ADR-SEC-002).
    schema : PostgreSQL schema to use.  Defaults to ``tc_verifiable_log``.
    pool : optional pre-built ``psycopg_pool.ConnectionPool``.  Takes
        precedence over ``dsn`` (useful when several chains share a pool).

    The class is thread-safe within a process (in-memory lock around the
    Merkle tree) and across processes (``pg_advisory_xact_lock`` during
    append).
    """

    ENV_DSN = "TC_VERIFIABLE_LOG_DSN"

    def __init__(
        self,
        dsn: Optional[str] = None,
        *,
        schema: str = "tc_verifiable_log",
        pool: Optional[ConnectionPool] = None,
    ) -> None:
        # DSN и pool разрешаются лениво — см. `_get_pool()`.  Это позволяет
        # безопасно инстанциировать `TrustChain(chain_storage='postgres')` в
        # тестах / кодовых путях, которые никогда не трогают цепочку.  Ошибка
        # «нет DSN» бросается только на первом реальном обращении (append /
        # verify / log …).
        self._dsn: Optional[str] = dsn
        self._schema = schema
        self._pool: Optional[ConnectionPool] = pool
        self._owns_pool = pool is None
        self._initialized = False
        # RLock: `_get_pool` может быть вызван из методов, уже удерживающих
        # `self._lock` (например, append).
        self._lock = threading.RLock()

        # Cached Merkle state (rebuilt from DB on first load / after rebuild_index).
        self._leaf_hashes: List[str] = []
        self._merkle_tree: Optional[MerkleTree] = None
        self._length = 0

    # ── Lazy init helpers ────────────────────────────────────────────────

    def _get_pool(self) -> ConnectionPool:
        """Ленивая инициализация connection-pool + схемы + Merkle-состояния."""
        if self._pool is not None and self._initialized:
            return self._pool
        with self._lock:
            if self._pool is None:
                dsn = self._dsn or os.environ.get(self.ENV_DSN)
                if not dsn:
                    raise RuntimeError(
                        "PostgresVerifiableChainStore requires a PostgreSQL DSN — "
                        f"set env {self.ENV_DSN} or pass dsn=... "
                        "(ADR-SEC-002 / ADR-SEC-005)."
                    )
                self._pool = ConnectionPool(
                    dsn,
                    min_size=1,
                    max_size=8,
                    kwargs={"autocommit": False},
                    open=True,
                )
                self._owns_pool = True
            if not self._initialized:
                self._ensure_schema()
                self._load_state()
                self._initialized = True
        return self._pool

    # ══════════════════════════════════════════════════════════════
    # Write path
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
        """Append an operation to the verifiable log (PG transactional)."""
        pool = self._get_pool()
        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()

            if parent_hash is None and self._merkle_tree is not None:
                parent_hash = self._merkle_tree.root

            with pool.connection() as conn:
                conn.autocommit = False
                with conn.cursor() as cur:
                    # Cross-process serialization of appends on this chain.
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,)
                    )

                    cur.execute(
                        "SELECT COALESCE(MAX(seq), 0) + 1 FROM chain_records"
                    )
                    seq = int(cur.fetchone()[0])

                    op_id = _content_id(tool, data, timestamp, signature)

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
                    record_json = json.dumps(record, sort_keys=True, default=str)
                    leaf_hash = hash_data(record_json)

                    cur.execute(
                        """
                        INSERT INTO chain_records (
                            seq, op_id, tool, ts, signature, session_id,
                            latency_ms, leaf_hash, record_json
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            seq,
                            op_id,
                            tool,
                            timestamp,
                            signature,
                            session_id,
                            latency_ms,
                            leaf_hash,
                            record_json,
                        ),
                    )

                    self._leaf_hashes.append(leaf_hash)
                    self._merkle_tree = MerkleTree.from_chunks(list(self._leaf_hashes))
                    self._length = seq

                    cur.execute(
                        """
                        INSERT INTO chain_head (id, merkle_root, length, updated_at)
                        VALUES ('HEAD', %s, %s, now())
                        ON CONFLICT (id) DO UPDATE
                        SET merkle_root = EXCLUDED.merkle_root,
                            length      = EXCLUDED.length,
                            updated_at  = now()
                        """,
                        (self._merkle_tree.root, seq),
                    )
                conn.commit()

            return record

    # ══════════════════════════════════════════════════════════════
    # Read path
    # ══════════════════════════════════════════════════════════════

    def log(
        self,
        limit: int = 20,
        offset: int = 0,
        tool: Optional[str] = None,
        session_id: Optional[str] = None,
        reverse: bool = True,
    ) -> List[dict]:
        """Query chain history — indexed, paginated."""
        clauses = ["1=1"]
        params: list = []
        if tool:
            clauses.append("tool = %s")
            params.append(tool)
        if session_id:
            clauses.append("session_id = %s")
            params.append(session_id)

        order = "DESC" if reverse else "ASC"
        sql = (
            "SELECT record_json FROM chain_records WHERE "
            + " AND ".join(clauses)
            + f" ORDER BY seq {order} LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])

        with self._get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        return [json.loads(row[0]) for row in rows]

    def show(self, op_id: str) -> Optional[dict]:
        with self._get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT record_json FROM chain_records WHERE op_id = %s",
                    (op_id,),
                )
                row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def blame(self, tool: str, limit: int = 50) -> List[dict]:
        return self.log(limit=limit, tool=tool, reverse=True)

    def status(self) -> dict:
        with self._get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COUNT(*)                              AS total,
                        COUNT(DISTINCT tool)                  AS tools,
                        MIN(ts)                               AS first_op,
                        MAX(ts)                               AS last_op,
                        COALESCE(AVG(latency_ms), 0)          AS avg_latency
                    FROM chain_records
                    """
                )
                stats = cur.fetchone()

                cur.execute(
                    """
                    SELECT tool, COUNT(*) AS cnt
                    FROM chain_records
                    GROUP BY tool
                    ORDER BY cnt DESC
                    """
                )
                tool_rows = cur.fetchall()

                cur.execute(
                    "SELECT pg_total_relation_size('chain_records')"
                )
                table_bytes = int(cur.fetchone()[0] or 0)

        first_op = stats[2].isoformat() if stats[2] else None
        last_op = stats[3].isoformat() if stats[3] else None

        return {
            "length": int(stats[0] or 0),
            "tools_count": int(stats[1] or 0),
            "first_operation": first_op,
            "last_operation": last_op,
            "avg_latency_ms": round(float(stats[4] or 0), 2),
            "merkle_root": self.merkle_root,
            "tools": {row[0]: int(row[1]) for row in tool_rows},
            "log_size_bytes": table_bytes,
            "index_size_bytes": table_bytes,
        }

    def diff(self, op_id_a: str, op_id_b: str) -> dict:
        a = self.show(op_id_a)
        b = self.show(op_id_b)
        if not a or not b:
            return {"error": "Operation not found", "a": op_id_a, "b": op_id_b}

        changes: Dict[str, Dict[str, Any]] = {}
        for key in sorted(set(list(a.keys()) + list(b.keys()))):
            va, vb = a.get(key), b.get(key)
            if va != vb:
                changes[key] = {"a": va, "b": vb}
        return {"op_a": op_id_a, "op_b": op_id_b, "changes": changes}

    # ══════════════════════════════════════════════════════════════
    # Cryptographic verification
    # ══════════════════════════════════════════════════════════════

    def verify(self) -> dict:
        """Recompute Merkle root from ``record_json`` and compare with HEAD row."""
        self._get_pool()
        if self._length == 0:
            return {
                "valid": True,
                "length": 0,
                "root": None,
                "method": "empty_chain",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }

        recomputed_leaves: List[str] = [
            hash_data(record_json) for record_json in self._iter_log_records()
        ]
        recomputed_tree = MerkleTree.from_chunks(list(recomputed_leaves))

        stored_root = self._load_head_root()
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
        pool = self._get_pool()
        if self._merkle_tree is None:
            return None

        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT seq FROM chain_records WHERE op_id = %s", (op_id,)
                )
                row = cur.fetchone()
        if not row:
            return None
        leaf_index = int(row[0]) - 1
        if leaf_index >= len(self._leaf_hashes):
            return None

        proof = self._merkle_tree.get_proof(leaf_index)
        return InclusionProof(
            op_id=op_id,
            leaf_index=leaf_index,
            merkle_proof=proof,
            chain_length=self._length,
            root_at_proof_time=self._merkle_tree.root,
        )

    def consistency_proof(self, old_length: int, old_root: str) -> dict:
        self._get_pool()
        if old_length > self._length:
            return {
                "consistent": False,
                "reason": f"old_length {old_length} > current {self._length}",
            }
        if old_length == 0:
            return {"consistent": True, "reason": "empty_prefix"}

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
        """Reload in-memory Merkle tree from the source-of-truth table.

        There is no separate ``index`` anymore — the table itself is the
        index.  This method only refreshes the in-memory Merkle leaves; it is
        safe to call after an out-of-band backup restore or TRUNCATE of a
        replica.
        """
        self._get_pool()
        with self._lock:
            self._load_state()
        return {"rebuilt": True, "records": self._length}

    def export_json(self, filepath: Optional[str] = None) -> str:
        records = self.log(limit=10**9, reverse=False)
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
            from pathlib import Path
            Path(filepath).write_text(output, encoding="utf-8")
        return output

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def head(self) -> Optional[str]:
        return self._merkle_tree.root if self._merkle_tree else None

    @property
    def merkle_root(self) -> Optional[str]:
        return self.head

    @property
    def length(self) -> int:
        return self._length

    def close(self) -> None:
        if self._owns_pool and self._pool is not None:
            try:
                self._pool.close()
            except Exception:
                pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════
    # Internal helpers
    # ══════════════════════════════════════════════════════════════

    def _ensure_schema(self) -> None:
        with self._pool.connection() as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{self._schema}"')
                cur.execute(f'SET LOCAL search_path TO "{self._schema}"')
                cur.execute(_DDL)
            conn.autocommit = False

    def _load_state(self) -> None:
        self._leaf_hashes = []
        self._length = 0
        for record_json in self._iter_log_records():
            self._leaf_hashes.append(hash_data(record_json))
            self._length += 1
        self._merkle_tree = (
            MerkleTree.from_chunks(list(self._leaf_hashes))
            if self._leaf_hashes
            else None
        )

    def _iter_log_records(self) -> Iterable[str]:
        """Stream ``record_json`` rows in ``seq`` order."""
        with self._pool.connection() as conn:
            with conn.cursor(name="chain_records_iter") as cur:
                cur.execute(
                    "SELECT record_json FROM chain_records ORDER BY seq ASC"
                )
                for (record_json,) in cur:
                    yield record_json

    def _load_head_root(self) -> Optional[str]:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT merkle_root FROM chain_head WHERE id = 'HEAD'"
                )
                row = cur.fetchone()
        return row[0] if row else None
