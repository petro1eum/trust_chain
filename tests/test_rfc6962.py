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
