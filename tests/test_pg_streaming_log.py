"""Bounded-state PostgreSQL log: real database, Ed25519, failures and concurrency."""

import json
import threading

import psycopg
import pytest

from trustchain.v2 import rfc6962
from trustchain.v2.merkle import MerkleTree, hash_data
from trustchain.v2.pg_verifiable_log import PostgresVerifiableChainStore
from trustchain.v2.signer import Signer

pytestmark = pytest.mark.integration


def append(store, index):
    return store.append("test", {"i": index, "text": "Проверка"}, f"sig-{index}")


@pytest.mark.parametrize("scheme", ["legacy", "rfc6962"])
def test_database_proofs_and_restart_preserve_existing_bytes(
    postgres_chain_reset, scheme
):
    store = PostgresVerifiableChainStore(dsn=postgres_chain_reset, merkle_scheme=scheme)
    records = []
    roots = []
    try:
        for size in range(1, 34):
            records.append(append(store, size))
            roots.append(store.merkle_root)
            if size not in (1, 2, 3, 5, 8, 9, 17, 33):
                continue
            raw = list(store._iter_log_records())
            if scheme == "legacy":
                reference = MerkleTree.from_leaves([hash_data(r) for r in raw])
                assert store.merkle_root == reference.root
            else:
                leaves = [r.encode() for r in raw]
                assert store.merkle_root == rfc6962.merkle_tree_hash(leaves).hex()
            for index, (record, content) in enumerate(zip(records, raw)):
                proof = store.inclusion_proof(record["id"])
                assert proof.verify(content)
                assert not proof.verify(content.replace("Проверка", "Подмена") + " ")
                if scheme == "legacy":
                    assert (
                        proof.merkle_proof.to_dict()
                        == reference.get_proof(index).to_dict()
                    )
                else:
                    assert proof.audit_path == [
                        x.hex() for x in rfc6962.inclusion_proof(index, leaves)
                    ]
            for old_size in (1, max(1, size // 2), size):
                proof = store.consistency_proof(old_size, roots[old_size - 1])
                assert proof["consistent"]
                if scheme == "rfc6962":
                    assert proof["proof"] == [
                        x.hex() for x in rfc6962.consistency_proof(old_size, leaves)
                    ]
                assert not store.consistency_proof(old_size, "0" * 64)["consistent"]
        last_root = store.merkle_root
    finally:
        store.close()
    reopened = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
    try:
        assert reopened.merkle_root == last_root
        assert reopened.verify()["valid"]
        append(reopened, 34)
        assert reopened.verify()["length"] == 34
    finally:
        reopened.close()


@pytest.mark.parametrize("scheme", ["legacy", "rfc6962"])
def test_refresh_reads_only_new_rows_but_explicit_rebuild_reads_all(
    postgres_chain_reset, monkeypatch, scheme
):
    store = PostgresVerifiableChainStore(dsn=postgres_chain_reset, merkle_scheme=scheme)
    peer = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
    try:
        for i in range(5):
            append(store, i)
        streamed = []
        original = store._stream_records

        def observed(*args, **kwargs):
            for row in original(*args, **kwargs):
                streamed.append(row[0])
                yield row

        monkeypatch.setattr(store, "_stream_records", observed)
        store._load_state()
        assert streamed == []
        append(peer, 5)
        append(peer, 6)
        store._load_state()
        assert streamed == [6, 7]
        assert store.merkle_root == peer.merkle_root
        streamed.clear()
        store.rebuild_index()
        assert streamed == list(range(1, 8))
        assert len(store._frontier.peaks) <= 3
    finally:
        store.close()
        peer.close()


@pytest.mark.parametrize("scheme", ["legacy", "rfc6962"])
def test_failed_head_write_rolls_back_record_and_does_not_poison_cache(
    postgres_chain_reset, scheme
):
    store = PostgresVerifiableChainStore(dsn=postgres_chain_reset, merkle_scheme=scheme)
    try:
        append(store, 0)
        root = store.merkle_root
        with psycopg.connect(postgres_chain_reset) as conn:
            conn.execute(
                """CREATE FUNCTION reject_test_head() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'injected HEAD failure'; END $$"""
            )
            conn.execute(
                "CREATE TRIGGER reject_test_head BEFORE INSERT OR UPDATE ON chain_head FOR EACH ROW EXECUTE FUNCTION reject_test_head()"
            )
        try:
            with pytest.raises(
                psycopg.errors.RaiseException, match="injected HEAD failure"
            ):
                append(store, 1)
            assert store.length == 1 and store.merkle_root == root
        finally:
            with psycopg.connect(postgres_chain_reset) as conn:
                conn.execute("DROP TRIGGER reject_test_head ON chain_head")
                conn.execute("DROP FUNCTION reject_test_head()")
        assert len(store.log()) == 1
        append(store, 2)
        assert store.verify()["valid"]
        assert store.length == 2
    finally:
        store.close()


@pytest.mark.parametrize("scheme", ["legacy", "rfc6962"])
def test_real_ed25519_signatures_are_checked_and_wrong_key_is_rejected(
    postgres_chain_reset, scheme
):
    signer = Signer()
    store = PostgresVerifiableChainStore(dsn=postgres_chain_reset, merkle_scheme=scheme)
    parent = None
    try:
        for i in range(8):
            signed = signer.sign(
                "document",
                {"i": i, "text": "Договор"},
                parent_signature=parent,
                metadata={"purpose": "streaming-test"},
            )
            record = store.append(
                signed.tool_id,
                signed.data,
                signed.signature,
                signature_id=signed.signature_id,
                parent_hash=parent,
                nonce=signed.nonce,
                response_timestamp=signed.timestamp,
                metadata=signed.metadata,
            )
            parent = signed.signature
            assert store.inclusion_proof(record["id"]).verify(
                json.dumps(record, sort_keys=True, default=str)
            )
        result = store.verify(public_key=signer.get_public_key())
        assert result["valid"] and result["signatures_verified"] == 8
        assert result["signatures_unverifiable"] == 0
        wrong = store.verify(public_key=Signer().get_public_key())
        assert wrong["valid"] is False
        assert len(wrong["invalid_signatures"]) == 8
    finally:
        store.close()


@pytest.mark.parametrize("scheme", ["legacy", "rfc6962"])
def test_verify_snapshot_is_consistent_while_another_process_appends(
    postgres_chain_reset, monkeypatch, scheme
):
    store = PostgresVerifiableChainStore(dsn=postgres_chain_reset, merkle_scheme=scheme)
    peer = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
    try:
        for i in range(3):
            append(store, i)
        # Complete the peer's existing lazy DDL before starting the read snapshot.
        # ALTER TABLE would otherwise wait for that snapshot in this same thread.
        assert peer.length == 3
        original = store._stream_records
        injected = False

        def interleaved(*args, **kwargs):
            nonlocal injected
            for row in original(*args, **kwargs):
                if not injected:
                    injected = True
                    append(peer, 3)
                yield row

        monkeypatch.setattr(store, "_stream_records", interleaved)
        result = store.verify()
        assert result["valid"] and result["length"] == 3
        assert store.verify()["length"] == 4
    finally:
        store.close()
        peer.close()


def test_rfc_concurrent_independent_writers(postgres_chain_reset):
    first = PostgresVerifiableChainStore(
        dsn=postgres_chain_reset, merkle_scheme="rfc6962"
    )
    second = PostgresVerifiableChainStore(
        dsn=postgres_chain_reset, merkle_scheme="rfc6962"
    )
    assert first.length == second.length == 0
    errors = []

    def write(store, offset):
        try:
            for i in range(offset, offset + 20):
                append(store, i)
        except Exception as error:
            errors.append(error)

    threads = [
        threading.Thread(target=write, args=(first, 0)),
        threading.Thread(target=write, args=(second, 100)),
    ]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not errors and not any(thread.is_alive() for thread in threads)
        first._load_state()
        assert first.length == 40
        assert first.verify()["valid"]
    finally:
        first.close()
        second.close()


def test_cached_head_does_not_hide_history_tampering(postgres_chain_reset):
    from tests.conftest import _PG_STATE

    store = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
    try:
        for i in range(3):
            append(store, i)
        # Test-container admin only; no production trigger is ever disabled.
        with psycopg.connect(_PG_STATE["admin_dsn"]) as conn:
            conn.execute(
                "ALTER TABLE tc_verifiable_log.chain_records DISABLE TRIGGER chain_records_no_mutation"
            )
            conn.execute(
                "UPDATE tc_verifiable_log.chain_records SET record_json = record_json || ' ' WHERE seq=1"
            )
            conn.execute(
                "ALTER TABLE tc_verifiable_log.chain_records ENABLE TRIGGER chain_records_no_mutation"
            )
        store._load_state()  # unchanged HEAD can reuse the cache, as intended
        assert store.verify()["valid"] is False  # integrity must still stream every row
    finally:
        store.close()
