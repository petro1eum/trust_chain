"""RFC 6962 (Certificate Transparency) Merkle Tree Hash + inclusion proofs.

Correct, standards-conformant primitives operating on RAW BYTES with 0x00/0x01
leaf/node domain separation, and — unlike the legacy trustchain.v2.merkle tree —
the root COMMITS TO THE LEAF COUNT (RFC 6962 splits at the largest power of two,
it does not duplicate the lone odd node). This closes the CVE-2012-2459-class
malleability where root([a,b,c]) == root([a,b,c,c]).

New module: nothing depends on it until opted in, so every existing (legacy) root
is byte-identical. See SPEC-CHAIN-INTEGRITY-1 R1.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || data)."""
    return _sha256(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
    return _sha256(b"\x01" + left + right)


def _largest_power_of_two_below(n: int) -> int:
    """Largest k = 2^b with k < n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 §2.1 Merkle Tree Hash (MTH) over a list of leaf DATA (raw bytes)."""
    n = len(leaves)
    if n == 0:
        return _sha256(b"")  # MTH({}) = SHA-256() of the empty string
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_below(n)
    return node_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def inclusion_proof(leaf_index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.1 audit path PATH(m, D[n]) — siblings ordered leaf→root."""
    n = len(leaves)
    if not (0 <= leaf_index < n):
        raise IndexError("leaf_index out of range")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if leaf_index < k:
        return inclusion_proof(leaf_index, leaves[:k]) + [merkle_tree_hash(leaves[k:])]
    return inclusion_proof(leaf_index - k, leaves[k:]) + [merkle_tree_hash(leaves[:k])]


def _recompute(
    m: int, n: int, acc: bytes, proof: list[bytes]
) -> tuple[bytes, list[bytes]]:
    if n == 1:
        return acc, proof
    k = _largest_power_of_two_below(n)
    if m < k:
        left, proof = _recompute(m, k, acc, proof)
        sib, proof = proof[0], proof[1:]
        return node_hash(left, sib), proof
    right, proof = _recompute(m - k, n - k, acc, proof)
    sib, proof = proof[0], proof[1:]
    return node_hash(sib, right), proof


def verify_inclusion(
    leaf_index: int,
    tree_size: int,
    leaf_data: bytes,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Verify an RFC 6962 inclusion proof by recomputing the root from the leaf."""
    if not (0 <= leaf_index < tree_size):
        return False
    computed, remaining = _recompute(
        leaf_index, tree_size, leaf_hash(leaf_data), list(proof)
    )
    return len(remaining) == 0 and computed == root
