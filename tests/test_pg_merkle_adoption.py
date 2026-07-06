"""Postgres store adoption of the RFC 6962 Merkle scheme (SPEC-CHAIN-INTEGRITY-1).

Mirrors tests/test_merkle_adoption.py for PostgresVerifiableChainStore: the
default stays legacy (byte-identical roots), rfc6962 is opt-in and persisted in
chain_head.merkle_scheme, the root commits to the leaf count (R1), and the
consistency proof is independently witness-verifiable (R4).

Integration tests — need a live Postgres (testcontainers); skipped without Docker.
"""

from __future__ import annotations

import pytest

from trustchain.v2 import rfc6962
from trustchain.v2.merkle import MerkleTree, hash_data
from trustchain.v2.pg_verifiable_log import PostgresVerifiableChainStore
from trustchain.v2.verifiable_log import MERKLE_SCHEME_LEGACY, MERKLE_SCHEME_RFC6962

pytestmark = pytest.mark.integration


def _fill(store: PostgresVerifiableChainStore, start: int, count: int) -> list[dict]:
    # Distinct i per record: op_id is content-addressed over (tool|data|signature)
    # and timestamp-independent, so overlapping i would collide the UNIQUE op_id.
    return [
        store.append(f"t{i}", {"i": i, "x": "y" * i}, f"s{i}", f"sid{i}")
        for i in range(start, start + count)
    ]


def _records(store: PostgresVerifiableChainStore) -> list[str]:
    return list(store._iter_log_records())


def test_pg_default_scheme_is_legacy(postgres_chain_reset: str):
    store = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
    try:
        _fill(store, 0, 4)
        assert store._scheme == MERKLE_SCHEME_LEGACY
        recs = _records(store)
        expected = MerkleTree.from_leaves([hash_data(r) for r in recs]).root
        assert store.merkle_root == expected
        assert store.verify()["method"] == "merkle_root_comparison"
        assert store.verify()["valid"] is True
    finally:
        store.close()


def test_pg_rfc6962_uses_the_new_tree(postgres_chain_reset: str):
    store = PostgresVerifiableChainStore(
        dsn=postgres_chain_reset, merkle_scheme="rfc6962"
    )
    try:
        _fill(store, 0, 6)
        assert store._scheme == MERKLE_SCHEME_RFC6962
        recs = _records(store)
        rfc_root = rfc6962.merkle_tree_hash([r.encode("utf-8") for r in recs]).hex()
        legacy_root = MerkleTree.from_leaves([hash_data(r) for r in recs]).root
        assert store.merkle_root == rfc_root
        assert store.merkle_root != legacy_root
        v = store.verify()
        assert v["valid"] is True
        assert v["method"] == "rfc6962_merkle_root"
    finally:
        store.close()


def test_pg_scheme_persists_across_reopen(postgres_chain_reset: str):
    store = PostgresVerifiableChainStore(
        dsn=postgres_chain_reset, merkle_scheme="rfc6962"
    )
    try:
        _fill(store, 0, 3)
        root = store.merkle_root
    finally:
        store.close()
    reopened = PostgresVerifiableChainStore(dsn=postgres_chain_reset)  # no scheme arg
    try:
        # ``merkle_root`` triggers lazy init (pool + scheme resolution).
        assert reopened.merkle_root == root
        assert reopened._scheme == MERKLE_SCHEME_RFC6962
        assert reopened.verify()["valid"] is True
    finally:
        reopened.close()


def test_pg_preexisting_stays_legacy(postgres_chain_reset: str):
    store = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
    try:
        _fill(store, 0, 4)
        original = store.merkle_root
    finally:
        store.close()
    # Even asking for rfc6962, a log whose chain_head already records legacy
    # must stay legacy (root byte-identical).
    reopened = PostgresVerifiableChainStore(
        dsn=postgres_chain_reset, merkle_scheme="rfc6962"
    )
    try:
        assert reopened.merkle_root == original  # triggers lazy init
        assert reopened._scheme == MERKLE_SCHEME_LEGACY
    finally:
        reopened.close()


def test_pg_rfc6962_consistency_independently_verifiable(postgres_chain_reset: str):
    store = PostgresVerifiableChainStore(
        dsn=postgres_chain_reset, merkle_scheme="rfc6962"
    )
    try:
        _fill(store, 0, 3)
        old_len, old_root = store.length, store.merkle_root
        _fill(store, 3, 4)  # distinct i=3..6 -> distinct op_ids
        new_len, new_root = store.length, store.merkle_root

        proof = store.consistency_proof(old_len, old_root)
        assert proof["scheme"] == MERKLE_SCHEME_RFC6962
        assert proof["consistent"] is True
        assert proof["proof"]
        assert (
            rfc6962.store_verify_consistency(
                old_len, new_len, old_root, new_root, proof["proof"]
            )
            is True
        )
        forged_old = "0" * len(old_root)
        assert (
            rfc6962.store_verify_consistency(
                old_len, new_len, forged_old, new_root, proof["proof"]
            )
            is False
        )
    finally:
        store.close()


def test_pg_rfc6962_inclusion_roundtrip_and_tamper(postgres_chain_reset: str):
    store = PostgresVerifiableChainStore(
        dsn=postgres_chain_reset, merkle_scheme="rfc6962"
    )
    try:
        ops = _fill(store, 0, 7)
        recs = _records(store)
        for op, rec in zip(ops, recs):
            proof = store.inclusion_proof(op["id"])
            assert proof is not None
            assert proof.verify(rec) is True
            assert proof.verify(rec.replace('"t', '"T', 1)) is False
    finally:
        store.close()
