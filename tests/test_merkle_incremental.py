"""RFC-003 BF-19: MerkleTree.append_leaf is O(log n) and identical to from_leaves."""

from __future__ import annotations

import time

from trustchain.v2.merkle import MerkleTree, hash_data


def _leaf(i: int) -> str:
    return hash_data(f"leaf-{i}")


def test_incremental_append_matches_from_leaves():
    inc = MerkleTree.from_leaves([])
    for n in range(1, 65):
        inc.append_leaf(_leaf(n - 1))
        full = MerkleTree.from_leaves([_leaf(i) for i in range(n)])
        assert inc.root == full.root, f"root mismatch at n={n}"
        assert inc.levels == full.levels, f"levels mismatch at n={n}"
        for idx in range(n):
            assert (
                inc.get_proof(idx).to_dict() == full.get_proof(idx).to_dict()
            ), f"proof {idx} mismatch at n={n}"


def test_incremental_append_proofs_verify():
    from trustchain.v2.merkle import verify_proof

    inc = MerkleTree.from_leaves([])
    chunks = [f"chunk-{i}" for i in range(20)]
    for c in chunks:
        inc.append_leaf(hash_data(c))
    for idx, c in enumerate(chunks):
        assert verify_proof(c, inc.get_proof(idx), inc.root)


def test_incremental_append_is_not_quadratic():
    # Sanity: 4000 incremental appends are far cheaper than 4000 full rebuilds.
    inc = MerkleTree.from_leaves([])
    t0 = time.perf_counter()
    for i in range(4000):
        inc.append_leaf(_leaf(i))
    incremental = time.perf_counter() - t0

    leaves = [_leaf(i) for i in range(4000)]
    t0 = time.perf_counter()
    for n in range(1, 4001):
        MerkleTree.from_leaves(leaves[:n])
    rebuild = time.perf_counter() - t0

    # Incremental should be at least ~5x faster than rebuild-every-append.
    assert incremental * 5 < rebuild, (incremental, rebuild)
