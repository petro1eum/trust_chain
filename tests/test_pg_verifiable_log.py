"""Integration tests for :class:`PostgresVerifiableChainStore`.

Run with a real Postgres (via testcontainers fixture in ``conftest.py``).
Skipped automatically when Docker is unavailable.
"""

from __future__ import annotations

import json

import pytest

from trustchain.v2.pg_verifiable_log import (
    InclusionProof,
    PostgresVerifiableChainStore,
)

pytestmark = pytest.mark.integration


# ─────────────────────────────────────────────────────────────────────────────
#  Basic CRUD
# ─────────────────────────────────────────────────────────────────────────────
class TestBasic:
    def test_append_roundtrip(self, postgres_chain_reset: str) -> None:
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            record = vlog.append("bash_tool", {"cmd": "ls"}, "sig_abc", "sigid_1")
            assert record["tool"] == "bash_tool"
            assert record["data"] == {"cmd": "ls"}
            assert record["seq"] == 1
            assert len(record["id"]) == 64  # full sha256 hex
            int(record["id"], 16)  # well-formed hex
        finally:
            vlog.close()

    def test_sequential_seq(self, postgres_chain_reset: str) -> None:
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            seqs = [
                vlog.append("t", {"i": i}, f"sig_{i}", f"sid_{i}")["seq"]
                for i in range(5)
            ]
        finally:
            vlog.close()
        assert seqs == [1, 2, 3, 4, 5]

    def test_show_and_missing(self, postgres_chain_reset: str) -> None:
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            r = vlog.append("test", {"k": "v"}, "sig", "sid")
            found = vlog.show(r["id"])
            assert found is not None
            assert found["tool"] == "test"
            assert vlog.show("nonexistent") is None
        finally:
            vlog.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Merkle / verification
# ─────────────────────────────────────────────────────────────────────────────
class TestVerification:
    def test_root_changes_with_appends(self, postgres_chain_reset: str) -> None:
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            assert vlog.merkle_root is None
            vlog.append("t", {"i": 1}, "s1", "si1")
            r1 = vlog.merkle_root
            vlog.append("t", {"i": 2}, "s2", "si2")
            r2 = vlog.merkle_root
            assert r1 != r2
            assert r1 is not None and r2 is not None
        finally:
            vlog.close()

    def test_verify_ok(self, postgres_chain_reset: str) -> None:
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            for i in range(4):
                vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")
            result = vlog.verify()
        finally:
            vlog.close()
        assert result["valid"] is True
        assert result["length"] == 4
        assert result["stored_root"] == result["computed_root"]

    def test_inclusion_proof(self, postgres_chain_reset: str) -> None:
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            records = [
                vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}") for i in range(5)
            ]
            target = records[2]
            proof = vlog.inclusion_proof(target["id"])
            assert proof is not None
            assert isinstance(proof, InclusionProof)
            target_record = vlog.show(target["id"])
            assert target_record is not None
            rec_json = json.dumps(target_record, sort_keys=True, default=str)
            assert proof.verify(rec_json) is True
        finally:
            vlog.close()

    def test_consistency_proof(self, postgres_chain_reset: str) -> None:
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            for i in range(3):
                vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")
            old_root = vlog.merkle_root
            old_length = vlog.length
            for i in range(3, 6):
                vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")

            result = vlog.consistency_proof(old_length, old_root)  # type: ignore[arg-type]
        finally:
            vlog.close()
        assert result["consistent"] is True


# ─────────────────────────────────────────────────────────────────────────────
#  Append-only enforcement (ADR-SEC-005)
# ─────────────────────────────────────────────────────────────────────────────
class TestAppendOnly:
    def test_direct_update_blocked_by_trigger(self, postgres_chain_reset: str) -> None:
        import psycopg

        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            vlog.append("t", {"x": 1}, "sig", "sid")
            with psycopg.connect(postgres_chain_reset) as conn, conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException):
                    cur.execute("UPDATE chain_records SET tool = 'tampered'")
                conn.rollback()
                with pytest.raises(psycopg.errors.RaiseException):
                    cur.execute("DELETE FROM chain_records")
                conn.rollback()
        finally:
            vlog.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Persistence across instances
# ─────────────────────────────────────────────────────────────────────────────
class TestPersistence:
    def test_reopen_preserves_state(self, postgres_chain_reset: str) -> None:
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            for i in range(3):
                vlog.append("t", {"i": i}, f"s_{i}", f"si_{i}")
            root = vlog.merkle_root
            length = vlog.length
        finally:
            vlog.close()

        reopened = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            assert reopened.length == length
            assert reopened.merkle_root == root
            assert reopened.verify()["valid"] is True
        finally:
            reopened.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Fail-closed when DSN is missing (ADR-SEC-002)
# ─────────────────────────────────────────────────────────────────────────────
def test_missing_dsn_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TC_VERIFIABLE_LOG_DSN", raising=False)
    with pytest.raises(RuntimeError, match="TC_VERIFIABLE_LOG_DSN"):
        PostgresVerifiableChainStore()
