"""Store-level adoption of the RFC 6962 Merkle scheme (SPEC-CHAIN-INTEGRITY-1).

Verifies that ``VerifiableChainStore`` can be opted into the standards-conformant
tree (root commits to leaf count + witness-verifiable consistency proofs) WITHOUT
changing the default: existing/legacy stores stay byte-identical. See R1/R4.
"""

from __future__ import annotations

from trustchain.v2 import rfc6962
from trustchain.v2.merkle import MerkleTree, hash_data
from trustchain.v2.verifiable_log import (
    MERKLE_SCHEME_LEGACY,
    MERKLE_SCHEME_RFC6962,
    VerifiableChainStore,
)


def _append(store: VerifiableChainStore, i: int) -> dict:
    return store.append(
        tool=f"tool{i}", data={"i": i, "x": "y" * i}, signature=f"sig{i}"
    )


def _records(store: VerifiableChainStore) -> list[str]:
    return list(store._iter_log_records())


# ── Non-breaking: the default is legacy and unchanged ─────────────────────────


def test_default_scheme_is_legacy_and_unchanged(tmp_path):
    store = VerifiableChainStore(str(tmp_path / "log"))
    assert store._scheme == MERKLE_SCHEME_LEGACY
    for i in range(5):
        _append(store, i)
    # Root is exactly the legacy tree over sha256(record_json) leaves.
    expected = MerkleTree.from_leaves([hash_data(r) for r in _records(store)]).root
    assert store.head == expected
    assert store.verify()["valid"] is True
    assert store.verify()["method"] == "merkle_root_comparison"


def test_preexisting_log_cannot_be_silently_flipped(tmp_path):
    # A store created before schemes existed has a chain.log but no MERKLE_SCHEME
    # file; reopening it — even asking for rfc6962 — must stay legacy so its HEAD
    # is byte-identical.
    root_dir = str(tmp_path / "log")
    store = VerifiableChainStore(root_dir)
    for i in range(4):
        _append(store, i)
    original_root = store.head
    store.close()
    (tmp_path / "log" / "MERKLE_SCHEME").unlink()  # simulate a pre-scheme store

    reopened = VerifiableChainStore(root_dir, merkle_scheme=MERKLE_SCHEME_RFC6962)
    assert reopened._scheme == MERKLE_SCHEME_LEGACY
    assert reopened.head == original_root


# ── Opt-in RFC 6962 store ─────────────────────────────────────────────────────


def test_rfc6962_store_uses_the_new_tree(tmp_path):
    store = VerifiableChainStore(str(tmp_path / "log"), merkle_scheme="rfc6962")
    assert store._scheme == MERKLE_SCHEME_RFC6962
    for i in range(6):
        _append(store, i)
    recs = _records(store)
    rfc_root = rfc6962.merkle_tree_hash([r.encode("utf-8") for r in recs]).hex()
    legacy_root = MerkleTree.from_leaves([hash_data(r) for r in recs]).root
    assert store.head == rfc_root  # it really is the RFC 6962 root ...
    assert store.head != legacy_root  # ... not the legacy one
    v = store.verify()
    assert v["valid"] is True
    assert v["method"] == "rfc6962_merkle_root"


def test_rfc6962_scheme_persists_across_reopen(tmp_path):
    root_dir = str(tmp_path / "log")
    store = VerifiableChainStore(root_dir, merkle_scheme="rfc6962")
    for i in range(3):
        _append(store, i)
    root = store.head
    store.close()
    reopened = VerifiableChainStore(root_dir)  # no arg — scheme read from disk
    assert reopened._scheme == MERKLE_SCHEME_RFC6962
    assert reopened.head == root
    assert reopened.verify()["valid"] is True


def test_env_var_selects_rfc6962(tmp_path, monkeypatch):
    monkeypatch.setenv("TC_MERKLE_SCHEME", "rfc6962")
    store = VerifiableChainStore(str(tmp_path / "log"))
    assert store._scheme == MERKLE_SCHEME_RFC6962


# ── R4: consistency proof is real + independently verifiable ──────────────────


def test_rfc6962_consistency_proof_is_independently_verifiable(tmp_path):
    store = VerifiableChainStore(str(tmp_path / "log"), merkle_scheme="rfc6962")
    for i in range(3):
        _append(store, i)
    old_len = store.length
    old_root = store.head
    for i in range(3, 7):
        _append(store, i)
    new_len = store.length
    new_root = store.head

    proof = store.consistency_proof(old_len, old_root)
    assert proof["scheme"] == MERKLE_SCHEME_RFC6962
    assert proof["consistent"] is True
    assert proof["proof"]  # a non-empty compact proof is present
    # A third party (the witness) verifies WITHOUT the leaves, from the two roots.
    assert (
        rfc6962.store_verify_consistency(
            old_len, new_len, old_root, new_root, proof["proof"]
        )
        is True
    )
    # A witness holding a DIFFERENT remembered old root must reject.
    forged_old = "0" * len(old_root)
    assert (
        rfc6962.store_verify_consistency(
            old_len, new_len, forged_old, new_root, proof["proof"]
        )
        is False
    )


def test_rfc6962_shrunk_or_bad_prefix_rejected(tmp_path):
    store = VerifiableChainStore(str(tmp_path / "log"), merkle_scheme="rfc6962")
    for i in range(5):
        _append(store, i)
    # old_length beyond current -> not consistent.
    assert store.consistency_proof(99, store.head)["consistent"] is False
    # A wrong old_root at a valid length -> self-check False.
    assert store.consistency_proof(2, "ab" * 32)["consistent"] is False


# ── R1 adoption: inclusion proofs verify against the size-committing root ─────


def test_rfc6962_inclusion_proof_roundtrip_and_tamper(tmp_path):
    store = VerifiableChainStore(str(tmp_path / "log"), merkle_scheme="rfc6962")
    ops = [_append(store, i) for i in range(7)]
    recs = _records(store)
    for op, rec in zip(ops, recs):
        proof = store.inclusion_proof(op["id"])
        assert proof is not None
        assert proof.verify(rec) is True
        # a tampered record must fail
        assert proof.verify(rec.replace("tool", "TOOL", 1)) is False
