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

import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    import psycopg  # noqa: F401 — required transitively for psycopg_pool runtime
    from psycopg_pool import ConnectionPool
except ImportError as exc:  # pragma: no cover — dep is declared in pyproject.toml
    raise ImportError(
        "PostgresVerifiableChainStore requires psycopg[binary,pool]; "
        "install trustchain[postgres] or add it to your project dependencies."
    ) from exc

from . import rfc6962
from .merkle import MerkleProof, MerkleTree, hash_data, verify_proof
from .verifiable_log import (
    MERKLE_SCHEME_LEGACY,
    MERKLE_SCHEME_RFC6962,
    Rfc6962InclusionProof,
)

_VALID_MERKLE_SCHEMES = frozenset({MERKLE_SCHEME_LEGACY, MERKLE_SCHEME_RFC6962})

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
    def from_dict(cls, data: dict) -> InclusionProof:
        return cls(
            op_id=data["op_id"],
            leaf_index=data["leaf_index"],
            merkle_proof=MerkleProof.from_dict(data["proof"]),
            chain_length=data["chain_length"],
            root_at_proof_time=data["root"],
        )


def _content_id(tool: str, data: Any, timestamp: str, signature: str) -> str:
    """Content-addressable op_id — sha256 hex.

    Delegates to :func:`trustchain.v2.verifiable_log.content_op_id` so the
    in-memory and PostgreSQL stores compute identical, signature-reproducible
    ids (see that function's docstring).
    """
    from .verifiable_log import content_op_id

    return content_op_id(tool, data, signature, timestamp)


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
    id            TEXT PRIMARY KEY CHECK (id = 'HEAD'),
    merkle_root   TEXT NOT NULL,
    length        BIGINT NOT NULL,
    merkle_scheme TEXT NOT NULL DEFAULT 'legacy',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Version-gate an existing (pre-scheme) deployment onto the column without a
-- migration: existing HEAD rows default to 'legacy', so their root stays
-- byte-identical (SPEC-CHAIN-INTEGRITY-1 R1/R4).
ALTER TABLE chain_head
    ADD COLUMN IF NOT EXISTS merkle_scheme TEXT NOT NULL DEFAULT 'legacy';

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
        dsn: str | None = None,
        *,
        schema: str = "tc_verifiable_log",
        pool: ConnectionPool | None = None,
        merkle_scheme: str | None = None,
    ) -> None:
        # Fail-closed: в enterprise-контракте (ADR-SEC-002) явное создание
        # ``PostgresVerifiableChainStore`` без DSN/pool — это misconfiguration.
        # ``TrustChain(chain_storage='postgres')`` сам делает graceful fallback
        # на in-memory, НЕ попадая сюда — см. ``trustchain.v2.core.TrustChain``.
        if pool is None and dsn is None and not os.environ.get(self.ENV_DSN):
            raise RuntimeError(
                "PostgresVerifiableChainStore requires a PostgreSQL DSN — "
                f"set env {self.ENV_DSN} or pass dsn=... "
                "(ADR-SEC-002 / ADR-SEC-005)."
            )
        # Соединение/схема поднимаются лениво в ``_get_pool()`` — это нужно,
        # чтобы конструктор не делал сетевой вызов и позволял реиспользовать
        # уже открытый pool между несколькими chain-сторами.
        self._dsn: str | None = dsn
        self._schema = schema
        self._pool: ConnectionPool | None = pool
        self._owns_pool = pool is None
        self._initialized = False
        # RLock: `_get_pool` может быть вызван из методов, уже удерживающих
        # `self._lock` (например, append).
        self._lock = threading.RLock()

        # Merkle scheme is resolved from the DB (or this request) on first load;
        # persisted immutably in chain_head.merkle_scheme. See R1/R4.
        self._requested_scheme = merkle_scheme
        self._scheme = MERKLE_SCHEME_LEGACY

        # Cached Merkle state (rebuilt from DB on first load / after rebuild_index).
        self._leaf_hashes: list[str] = []
        self._merkle_tree: MerkleTree | None = None
        self._rfc_leaves: list[bytes] = []
        self._rfc_root: str | None = None
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
                self._scheme = self._resolve_scheme()
                self._load_state()
                self._initialized = True
        return self._pool

    # ══════════════════════════════════════════════════════════════
    # Write path
    # ══════════════════════════════════════════════════════════════

    def append(
        self,
        tool: str,
        data: dict[str, Any],
        signature: str,
        signature_id: str = "",
        parent_hash: str | None = None,
        key_id: str = "",
        algorithm: str = "Ed25519",
        latency_ms: float = 0,
        session_id: str | None = None,
        nonce: str | None = None,
        metadata: dict[str, Any] | None = None,
        response_timestamp: float | None = None,
        certificate: dict[str, Any] | None = None,
        parent_signatures: list[str] | None = None,
    ) -> dict:
        """Append an operation to the verifiable log (PG transactional).

        ``response_timestamp`` / ``certificate`` — см. docstring
        :meth:`ChainStore.commit`.  Оба поля опциональны; если переданы,
        запишем их в ``record`` наряду с штатными.  Это не ломает ни leaf
        hash (он считается после сборки record_json), ни proof-ы старых
        записей — формат записи задаёт сам writer.
        """
        pool = self._get_pool()
        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()

            # The value passed by ChainStore.commit() as parent_hash is the
            # signer's actual parent_signature (may be None). Capture it before
            # we substitute the Merkle root, so signature re-verification can
            # reconstruct the canonical payload byte-for-byte.
            signed_parent = parent_hash

            with pool.connection() as conn:
                conn.autocommit = False
                with conn.cursor() as cur:
                    # Cross-process serialization of appends on this chain.
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,)
                    )
                    # Another process may have appended since this instance last
                    # loaded its in-memory Merkle state. Catch up only after the
                    # database lock is held; otherwise this writer can persist a
                    # root computed from a stale leaf prefix.
                    self._catch_up_state(cur)

                    if parent_hash is None:
                        prev_root = self._current_root()
                        if prev_root is not None:
                            parent_hash = prev_root

                    cur.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM chain_records")
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
                    # Persist the signer's actual parent linkage so the
                    # signature can be re-verified later (parent_hash above may
                    # hold the Merkle root rather than the signed parent).
                    record["parent_signature"] = signed_parent
                    if parent_signatures is not None:
                        record["parent_signatures"] = parent_signatures
                    if response_timestamp is not None:
                        record["response_timestamp"] = float(response_timestamp)
                    if certificate is not None:
                        record["certificate"] = certificate
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

                    if self._scheme == MERKLE_SCHEME_RFC6962:
                        # RFC 6962 leaf = the record bytes; the root commits to
                        # the leaf count (SPEC-CHAIN-INTEGRITY-1 R1).
                        self._rfc_leaves.append(record_json.encode("utf-8"))
                        self._rfc_root = rfc6962.merkle_tree_hash(
                            self._rfc_leaves
                        ).hex()
                        new_root = self._rfc_root
                    else:
                        self._leaf_hashes.append(leaf_hash)
                        # ``_leaf_hashes`` уже содержит ``sha256(record_json)``.
                        # Инкрементный append_leaf даёт тот же root/proofs, что
                        # from_leaves, но за O(log n) вместо O(n) (RFC-003 BF-19);
                        # fallback на from_leaves при рассинхроне (после _load_state).
                        if (
                            self._merkle_tree is not None
                            and len(self._merkle_tree.leaves)
                            == len(self._leaf_hashes) - 1
                        ):
                            self._merkle_tree.append_leaf(leaf_hash)
                        else:
                            self._merkle_tree = MerkleTree.from_leaves(
                                list(self._leaf_hashes)
                            )
                        new_root = self._merkle_tree.root
                    self._length = seq

                    cur.execute(
                        """
                        INSERT INTO chain_head
                            (id, merkle_root, length, merkle_scheme, updated_at)
                        VALUES ('HEAD', %s, %s, %s, now())
                        ON CONFLICT (id) DO UPDATE
                        SET merkle_root = EXCLUDED.merkle_root,
                            length      = EXCLUDED.length,
                            updated_at  = now()
                        """,
                        (new_root, seq, self._scheme),
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
        tool: str | None = None,
        session_id: str | None = None,
        reverse: bool = True,
    ) -> list[dict]:
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
        # clauses are static templates with %s placeholders; order is one of two literals.
        where_clause = " AND ".join(clauses)
        sql = f"SELECT record_json FROM chain_records WHERE {where_clause} ORDER BY seq {order} LIMIT %s OFFSET %s"  # nosec B608
        params.extend([limit, offset])

        with self._get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        return [json.loads(row[0]) for row in rows]

    def show(self, op_id: str) -> dict | None:
        with self._get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT record_json FROM chain_records WHERE op_id = %s",
                    (op_id,),
                )
                row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def blame(self, tool: str, limit: int = 50) -> list[dict]:
        return self.log(limit=limit, tool=tool, reverse=True)

    def status(self) -> dict:
        with self._get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT
                        COUNT(*)                              AS total,
                        COUNT(DISTINCT tool)                  AS tools,
                        MIN(ts)                               AS first_op,
                        MAX(ts)                               AS last_op,
                        COALESCE(AVG(latency_ms), 0)          AS avg_latency
                    FROM chain_records
                    """)
                stats = cur.fetchone()

                cur.execute("""
                    SELECT tool, COUNT(*) AS cnt
                    FROM chain_records
                    GROUP BY tool
                    ORDER BY cnt DESC
                    """)
                tool_rows = cur.fetchall()

                cur.execute("SELECT pg_total_relation_size('chain_records')")
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

        changes: dict[str, dict[str, Any]] = {}
        for key in sorted(set(list(a.keys()) + list(b.keys()))):
            va, vb = a.get(key), b.get(key)
            if va != vb:
                changes[key] = {"a": va, "b": vb}
        return {"op_a": op_id_a, "op_b": op_id_b, "changes": changes}

    # ══════════════════════════════════════════════════════════════
    # Cryptographic verification
    # ══════════════════════════════════════════════════════════════

    def verify(self, public_key: str | None = None) -> dict:
        """Verify the log integrity.

        Always: recompute the Merkle root from ``record_json`` and compare it
        with the stored HEAD root (tamper-evidence over the whole log).

        When ``public_key`` (base64 Ed25519) is provided, additionally
        re-verify every record's signature by reconstructing the canonical
        signed payload from the stored record. Without a public key, signatures
        are NOT re-verified — the result reflects Merkle integrity only.
        """
        self._get_pool()
        if self._length == 0:
            return {
                "valid": True,
                "length": 0,
                "root": None,
                "method": "empty_chain",
                "signatures_checked": bool(public_key),
                "signatures_verified": 0,
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }

        record_jsons = list(self._iter_log_records())
        if self._scheme == MERKLE_SCHEME_RFC6962:
            computed_root = rfc6962.merkle_tree_hash(
                [rj.encode("utf-8") for rj in record_jsons]
            ).hex()
            method = "rfc6962_merkle_root"
        else:
            computed_root = MerkleTree.from_leaves(
                [hash_data(rj) for rj in record_jsons]
            ).root
            method = "merkle_root_comparison"

        stored_root = self._load_head_root()
        valid = computed_root == stored_root

        sigs_verified = 0
        sigs_unverifiable = 0
        invalid_signatures: list[dict] = []
        if public_key:
            from .chain_store import verify_record_signature
            from .verifier import TrustChainVerifier

            verifier = TrustChainVerifier(public_key, max_age_seconds=None)
            for rj in record_jsons:
                try:
                    record = json.loads(rj)
                except Exception:
                    sigs_unverifiable += 1
                    continue
                res = verify_record_signature(record, verifier)
                if res is True:
                    sigs_verified += 1
                elif res is None:
                    sigs_unverifiable += 1
                else:
                    valid = False
                    invalid_signatures.append(
                        {
                            "id": record.get("id"),
                            "signature": record.get("signature"),
                            "error": "invalid_signature",
                        }
                    )

        return {
            "valid": valid,
            "length": len(record_jsons),
            "stored_root": stored_root,
            "computed_root": computed_root,
            "method": method,
            "signatures_checked": bool(public_key),
            "signatures_verified": sigs_verified,
            "signatures_unverifiable": sigs_unverifiable,
            "invalid_signatures": invalid_signatures,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def inclusion_proof(
        self, op_id: str
    ) -> InclusionProof | Rfc6962InclusionProof | None:
        pool = self._get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT seq FROM chain_records WHERE op_id = %s", (op_id,))
                row = cur.fetchone()
        if not row:
            return None
        leaf_index = int(row[0]) - 1

        if self._scheme == MERKLE_SCHEME_RFC6962:
            if leaf_index >= len(self._rfc_leaves) or self._rfc_root is None:
                return None
            audit_path = [
                h.hex() for h in rfc6962.inclusion_proof(leaf_index, self._rfc_leaves)
            ]
            return Rfc6962InclusionProof(
                op_id=op_id,
                leaf_index=leaf_index,
                tree_size=self._length,
                audit_path=audit_path,
                root_at_proof_time=self._rfc_root,
            )

        if self._merkle_tree is None:
            return None
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

        if self._scheme == MERKLE_SCHEME_RFC6962:
            return self._rfc6962_consistency_proof(old_length, old_root)

        if old_length == 0:
            return {"consistent": True, "reason": "empty_prefix"}

        old_tree = MerkleTree.from_leaves(list(self._leaf_hashes[:old_length]))
        consistent = old_tree.root == old_root
        return {
            "consistent": consistent,
            "old_length": old_length,
            "old_root": old_root,
            "recomputed_old_root": old_tree.root,
            "current_length": self._length,
            "current_root": self._merkle_tree.root if self._merkle_tree else None,
        }

    def _rfc6962_consistency_proof(self, old_length: int, old_root: str) -> dict:
        """RFC 6962 consistency proof (SPEC-CHAIN-INTEGRITY-1 R4).

        Returns the compact consistency ``proof`` so a witness can verify the
        append-only invariant INDEPENDENTLY against its OWN remembered old root
        instead of trusting a self-reported boolean.
        """
        current_root = self._current_root()
        if old_length == 0:
            return {
                "scheme": MERKLE_SCHEME_RFC6962,
                "consistent": True,
                "reason": "empty_prefix",
                "old_length": 0,
                "old_root": old_root,
                "current_length": self._length,
                "current_root": current_root,
                "proof": [],
            }
        proof_hex = [
            h.hex() for h in rfc6962.consistency_proof(old_length, self._rfc_leaves)
        ]
        recomputed_old_root = rfc6962.merkle_tree_hash(
            self._rfc_leaves[:old_length]
        ).hex()
        consistent = rfc6962.store_verify_consistency(
            old_length,
            self._length,
            old_root,
            current_root or "",
            proof_hex,
        )
        return {
            "scheme": MERKLE_SCHEME_RFC6962,
            "consistent": consistent,
            "old_length": old_length,
            "old_root": old_root,
            "recomputed_old_root": recomputed_old_root,
            "current_length": self._length,
            "current_root": current_root,
            "proof": proof_hex,
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

    def export_json(self, filepath: str | None = None) -> str:
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
    def head(self) -> str | None:
        # Lazy init: без этого ``reopened.merkle_root`` после close() возвращает
        # None, даже если в БД сохранены записи (см. test_reopen_preserves_state).
        self._get_pool()
        return self._current_root()

    @property
    def merkle_root(self) -> str | None:
        return self.head

    @property
    def length(self) -> int:
        self._get_pool()
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
                # В enterprise-deployments роль с которой ходит сервис часто
                # НЕ имеет CREATE на database (least privilege, ADR-SEC-002).
                # Схема создаётся заранее админом (см. docs/POSTGRES_MIGRATION.md),
                # поэтому сперва проверяем её существование и пробуем CREATE
                # только если схемы реально нет.
                cur.execute(
                    "SELECT 1 FROM pg_namespace WHERE nspname = %s",
                    (self._schema,),
                )
                schema_exists = cur.fetchone() is not None
                if not schema_exists:
                    try:
                        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{self._schema}"')
                    except Exception as exc:  # pragma: no cover - enterprise path
                        raise RuntimeError(
                            f"schema '{self._schema}' отсутствует, а роль не "
                            "имеет CREATE на database. Создайте схему заранее "
                            "(см. docs/POSTGRES_MIGRATION.md §Provisioning)."
                        ) from exc
                cur.execute(f'SET LOCAL search_path TO "{self._schema}"')
                cur.execute(_DDL)
            conn.autocommit = False

    def _catch_up_state(self, cur) -> None:
        """Catch up rows committed by other processes in the in-memory Merkle state.

        The caller must hold the append advisory lock in the current transaction.
        Reading after that lock closes the race between a stale process cache and
        a concurrent append without rebuilding the entire tree for every write.
        """
        cur.execute(
            "SELECT seq, record_json FROM chain_records "
            "WHERE seq > %s ORDER BY seq ASC",
            (self._length,),
        )
        rows = cur.fetchall()
        if not rows:
            return

        expected_seq = self._length + 1
        for seq, record_json in rows:
            seq = int(seq)
            if seq != expected_seq:
                raise RuntimeError(
                    "chain_records sequence gap while catching up Merkle state: "
                    f"expected {expected_seq}, got {seq}"
                )
            if self._scheme == MERKLE_SCHEME_RFC6962:
                self._rfc_leaves.append(record_json.encode("utf-8"))
            else:
                leaf_hash = hash_data(record_json)
                self._leaf_hashes.append(leaf_hash)
                if (
                    self._merkle_tree is not None
                    and len(self._merkle_tree.leaves) == len(self._leaf_hashes) - 1
                ):
                    self._merkle_tree.append_leaf(leaf_hash)
                else:
                    self._merkle_tree = MerkleTree.from_leaves(list(self._leaf_hashes))
            self._length = seq
            expected_seq += 1

        if self._scheme == MERKLE_SCHEME_RFC6962:
            self._rfc_root = rfc6962.merkle_tree_hash(self._rfc_leaves).hex()

    def _load_state(self) -> None:
        self._leaf_hashes = []
        self._rfc_leaves = []
        self._length = 0

        if self._scheme == MERKLE_SCHEME_RFC6962:
            for record_json in self._iter_log_records():
                self._rfc_leaves.append(record_json.encode("utf-8"))
                self._length += 1
            self._rfc_root = (
                rfc6962.merkle_tree_hash(self._rfc_leaves).hex()
                if self._rfc_leaves
                else None
            )
            self._merkle_tree = None
            return

        for record_json in self._iter_log_records():
            self._leaf_hashes.append(hash_data(record_json))
            self._length += 1
        self._merkle_tree = (
            MerkleTree.from_leaves(list(self._leaf_hashes))
            if self._leaf_hashes
            else None
        )

    def _resolve_scheme(self) -> str:
        """Determine this log's immutable Merkle scheme.

        Authoritative source is ``chain_head.merkle_scheme`` (present once the
        log has any records — a pre-scheme deployment reads the ``legacy``
        column default, so its root stays byte-identical). A fresh log honors
        the requested scheme / ``TC_MERKLE_SCHEME`` env / ``legacy`` default;
        that choice is persisted by the genesis ``append``.
        """
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT merkle_scheme FROM chain_head WHERE id = 'HEAD'")
                row = cur.fetchone()
        if row and row[0] in _VALID_MERKLE_SCHEMES:
            return row[0]
        scheme = self._requested_scheme or os.environ.get(
            "TC_MERKLE_SCHEME", MERKLE_SCHEME_LEGACY
        )
        if scheme not in _VALID_MERKLE_SCHEMES:
            raise ValueError(f"unknown merkle_scheme: {scheme!r}")
        return scheme

    def _current_root(self) -> str | None:
        """Current Merkle root (hex) for the active scheme, or None if empty."""
        if self._scheme == MERKLE_SCHEME_RFC6962:
            return self._rfc_root
        return self._merkle_tree.root if self._merkle_tree else None

    def _iter_log_records(self) -> Iterable[str]:
        """Stream ``record_json`` rows in ``seq`` order."""
        with self._pool.connection() as conn:
            with conn.cursor(name="chain_records_iter") as cur:
                cur.execute("SELECT record_json FROM chain_records ORDER BY seq ASC")
                for (record_json,) in cur:
                    yield record_json

    def _load_head_root(self) -> str | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT merkle_root FROM chain_head WHERE id = 'HEAD'")
                row = cur.fetchone()
        return row[0] if row else None
