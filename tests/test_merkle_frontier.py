"""Independent compatibility oracles and a retained-memory bound."""

import tracemalloc

import pytest

from trustchain.v2 import rfc6962
from trustchain.v2.merkle import MerkleTree, hash_data
from trustchain.v2.merkle_frontier import (
    MerkleFrontier,
    consistency_ranges,
    inclusion_ranges,
)


@pytest.mark.parametrize("scheme", ["legacy", "rfc6962"])
def test_every_prefix_matches_existing_tree_and_copy_is_independent(scheme):
    frontier = MerkleFrontier(scheme)
    assert frontier.root is None
    leaves = []
    for size in range(1, 258):
        previous = frontier.copy()
        previous_root = previous.root
        leaves.append(("Документ \x00 № " + str(size)).encode())
        frontier.append(leaves[-1])
        expected = (
            rfc6962.merkle_tree_hash(leaves).hex()
            if scheme == "rfc6962"
            else MerkleTree.from_leaves([hash_data(x.decode()) for x in leaves]).root
        )
        assert frontier.root == expected
        assert previous.root == previous_root
        assert previous.length == size - 1
        assert len(frontier.peaks) == size.bit_length()


@pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 9, 17, 32, 33, 65, 129])
def test_rfc_proof_ranges_match_existing_proofs_and_reject_tampering(size):
    leaves = [str(i).encode() for i in range(size)]
    root = rfc6962.merkle_tree_hash(leaves)
    for index in range(size):
        path = [
            rfc6962.merkle_tree_hash(leaves[start : start + count])
            for start, count in inclusion_ranges(index, size)
        ]
        assert path == rfc6962.inclusion_proof(index, leaves)
        assert rfc6962.verify_inclusion(index, size, leaves[index], path, root)
        assert not rfc6962.verify_inclusion(index, size, b"forged", path, root)
    for old_size in range(1, size + 1):
        proof = [
            rfc6962.merkle_tree_hash(leaves[start : start + count])
            for start, count in consistency_ranges(old_size, size)
        ]
        assert proof == rfc6962.consistency_proof(old_size, leaves)
        assert rfc6962.verify_consistency(
            old_size, size, rfc6962.merkle_tree_hash(leaves[:old_size]), root, proof
        )
        assert not rfc6962.verify_consistency(old_size, size, bytes(32), root, proof)


@pytest.mark.parametrize("scheme", ["legacy", "rfc6962"])
def test_history_is_not_retained_in_memory(scheme):
    # 80 MiB of input is consumed without retaining it. A full record list or
    # even an unbounded leaf-hash array would violate this independent budget.
    tracemalloc.start()
    try:
        frontier = MerkleFrontier(scheme)
        for index in range(10_000):
            frontier.append((str(index) + "x" * 8192).encode())
        retained, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert retained < 100_000
    assert peak < 1_000_000
    assert sum(len(node) for node in frontier.peaks if node) <= 32 * 14
