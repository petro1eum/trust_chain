"""Streaming Merkle state: one completed subtree per occupied binary digit.

Leaves and proof nodes remain in the caller's durable store. Both schemes keep
their existing byte-level hashing and odd-node rules; this is not a new scheme.
"""

from __future__ import annotations

from . import rfc6962
from .merkle import hash_pair


class MerkleFrontier:
    """O(log n) hashes for append/root, without retaining record bodies or leaves."""

    def __init__(self, scheme: str) -> None:
        if scheme not in ("legacy", "rfc6962"):
            raise ValueError(f"unknown merkle_scheme: {scheme!r}")
        self.scheme = scheme
        self.length = 0
        self.peaks: list[bytes | None] = []

    def copy(self) -> MerkleFrontier:
        result = MerkleFrontier(self.scheme)
        result.length = self.length
        result.peaks = list(self.peaks)
        return result

    def pair(self, left: bytes, right: bytes) -> bytes:
        if self.scheme == "rfc6962":
            return rfc6962.node_hash(left, right)
        # Legacy parents hash the ASCII HEX children, not their raw digest bytes.
        return bytes.fromhex(hash_pair(left.hex(), right.hex()))

    def append(self, record: bytes) -> None:
        self.append_leaf_hash(rfc6962.leaf_hash(record))

    def append_leaf_hash(self, node: bytes) -> None:
        """Fold a stored SHA-256 leaf digest without fetching its record body."""
        if len(node) != 32:
            raise ValueError("a Merkle leaf digest must contain 32 bytes")
        level = 0
        while level < len(self.peaks) and self.peaks[level] is not None:
            node = self.pair(self.peaks[level], node)
            self.peaks[level] = None
            level += 1
        if level == len(self.peaks):
            self.peaks.append(node)
        else:
            self.peaks[level] = node
        self.length += 1

    def root_bytes(self, *, pad_to_height: int | None = None) -> bytes | None:
        right = None
        height = 0
        for level, left in enumerate(self.peaks):
            if left is None:
                continue
            if right is None:
                right, height = left, level
                continue
            if self.scheme == "legacy":
                while height < level:
                    right = self.pair(right, right)
                    height += 1
            right = self.pair(left, right)
            height = level + 1
        if pad_to_height is not None:
            if self.scheme != "legacy" or pad_to_height < height:
                raise ValueError("padding is only defined for a legacy subtree")
            while right is not None and height < pad_to_height:
                right = self.pair(right, right)
                height += 1
        return right

    @property
    def root(self) -> str | None:
        root = self.root_bytes()
        return root.hex() if root is not None else None


def inclusion_ranges(index: int, size: int, start: int = 0) -> list[tuple[int, int]]:
    """RFC 6962 audit path as disjoint database ranges, in leaf-to-root order."""
    if not 0 <= index < size:
        raise IndexError("leaf_index out of range")
    if size == 1:
        return []
    split = 1 << ((size - 1).bit_length() - 1)
    if index < split:
        return inclusion_ranges(index, split, start) + [(start + split, size - split)]
    return inclusion_ranges(index - split, size - split, start + split) + [
        (start, split)
    ]


def consistency_ranges(
    old_size: int, size: int, start: int = 0, at_root: bool = True
) -> list[tuple[int, int]]:
    """RFC 6962 SUBPROOF expressed as ranges; payloads never enter the plan."""
    if not 0 < old_size <= size:
        raise ValueError("consistency proof requires 0 < old_size <= size")
    if old_size == size:
        return [] if at_root else [(start, size)]
    split = 1 << ((size - 1).bit_length() - 1)
    if old_size <= split:
        return consistency_ranges(old_size, split, start, at_root) + [
            (start + split, size - split)
        ]
    return consistency_ranges(old_size - split, size - split, start + split, False) + [
        (start, split)
    ]
