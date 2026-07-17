"""RFC 6962 Merkle primitives — conformance vectors + the commit-to-size property.

Verifies (a) published CT/RFC 6962 test vectors, (b) that the root COMMITS TO the
leaf count (the malleability the legacy trustchain.v2.merkle tree has), and
(c) exhaustive inclusion-proof round-trips + tamper rejection. See
SPEC-CHAIN-INTEGRITY-1 R1.
"""

from __future__ import annotations

import binascii

import pytest

from trustchain.v2 import rfc6962

# The canonical CT / RFC 6962 8-leaf test inputs.
_LEAVES = [
    binascii.unhexlify(x)
    for x in [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ]
]


def test_published_vectors():
    assert (
        rfc6962.merkle_tree_hash([]).hex()
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        rfc6962.leaf_hash(b"").hex()
        == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    )
    assert (
        rfc6962.merkle_tree_hash(_LEAVES).hex()
        == "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
    )


def test_root_commits_to_leaf_count():
    a, b, c = b"a", b"b", b"c"
    # legacy Bitcoin-style trees satisfy root([a,b,c]) == root([a,b,c,c]); RFC 6962 must not.
    assert rfc6962.merkle_tree_hash([a, b, c]) != rfc6962.merkle_tree_hash([a, b, c, c])


@pytest.mark.parametrize("n", range(1, 33))
def test_inclusion_roundtrip_and_tamper(n):
    leaves = [bytes([i, (255 - i) & 0xFF, (i * 7) & 0xFF]) for i in range(n)]
    root = rfc6962.merkle_tree_hash(leaves)
    for i in range(n):
        proof = rfc6962.inclusion_proof(i, leaves)
        assert rfc6962.verify_inclusion(i, n, leaves[i], proof, root) is True
        # a flipped leaf byte must fail
        bad_leaf = bytes([leaves[i][0] ^ 1]) + leaves[i][1:]
        assert rfc6962.verify_inclusion(i, n, bad_leaf, proof, root) is False
        # a tampered proof node must fail
        if proof:
            bad_proof = [bytes([proof[0][0] ^ 1]) + proof[0][1:], *proof[1:]]
            assert rfc6962.verify_inclusion(i, n, leaves[i], bad_proof, root) is False


def test_out_of_range_index():
    assert (
        rfc6962.verify_inclusion(3, 3, b"x", [], rfc6962.merkle_tree_hash([b"x"]))
        is False
    )


@pytest.mark.parametrize(
    ("tree_size", "proof"),
    [
        (2, []),
        (4, [b"\x00" * 32]),
        (2, [b"short"]),
    ],
)
def test_malformed_or_short_inclusion_proof_returns_false(tree_size, proof):
    leaves = [bytes([i]) for i in range(tree_size)]
    root = rfc6962.merkle_tree_hash(leaves)
    assert rfc6962.verify_inclusion(0, tree_size, leaves[0], proof, root) is False


def test_malformed_inclusion_root_returns_false():
    assert rfc6962.verify_inclusion(0, 1, b"x", [], b"short") is False


def test_store_inclusion_adapter_rejects_invalid_hex_type():
    assert rfc6962.store_verify_inclusion(0, 1, "x", [None], "00" * 32) is False


@pytest.mark.parametrize("n", range(1, 25))
def test_consistency_roundtrip_and_tamper(n):
    leaves = [bytes([i, (i * 3) & 0xFF]) for i in range(n)]
    new_root = rfc6962.merkle_tree_hash(leaves)
    for m in range(1, n + 1):
        old_root = rfc6962.merkle_tree_hash(leaves[:m])
        proof = rfc6962.consistency_proof(m, leaves)
        assert rfc6962.verify_consistency(m, n, old_root, new_root, proof) is True
        # a tampered old root must fail
        bad_old = bytes([old_root[0] ^ 1]) + old_root[1:]
        assert rfc6962.verify_consistency(m, n, bad_old, new_root, proof) is False
        if proof:
            bad_proof = [bytes([proof[0][0] ^ 1]) + proof[0][1:], *proof[1:]]
            assert (
                rfc6962.verify_consistency(m, n, old_root, new_root, bad_proof) is False
            )


def test_rewritten_prefix_is_rejected():
    # R4 security property: a forged (rewritten-prefix) tree cannot produce a
    # consistency proof that verifies against the HONEST old root.
    leaves = [bytes([i]) for i in range(8)]
    honest_old_root = rfc6962.merkle_tree_hash(leaves[:4])
    forged = [*leaves[:3], b"\xff\xff", *leaves[4:]]  # rewrite leaf 3
    forged_new_root = rfc6962.merkle_tree_hash(forged)
    forged_proof = rfc6962.consistency_proof(4, forged)
    assert (
        rfc6962.verify_consistency(4, 8, honest_old_root, forged_new_root, forged_proof)
        is False
    )
