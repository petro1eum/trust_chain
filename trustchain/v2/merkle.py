"""Merkle Tree implementation for TrustChain.

Enables partial verification of large documents/responses.
Instead of signing entire document, sign only the Merkle root.
Client can verify individual chunks without downloading everything.

Use cases:
- RAG systems with large documents
- LegalTech document verification
- IoT sensor data batches

Usage:
    from trustchain.v2.merkle import MerkleTree, verify_proof

    # Create tree from chunks
    chunks = ["page 1 content", "page 2 content", "page 3 content"]
    tree = MerkleTree.from_chunks(chunks)

    # Sign only the root
    signed = tc._signer.sign("document", {"merkle_root": tree.root})

    # Later: verify single chunk
    chunk_index = 1
    proof = tree.get_proof(chunk_index)
    is_valid = verify_proof(chunks[1], proof, tree.root)
"""

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


def hash_data(data: str) -> str:
    """Hash a string using SHA-256."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """Hash two hashes together."""
    combined = left + right
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


@dataclass
class MerkleProof:
    """Proof that a chunk belongs to a Merkle tree.

    Contains the path from leaf to root with sibling hashes.
    """

    chunk_index: int
    chunk_hash: str
    siblings: List[Tuple[str, str]]  # List of (hash, position: 'left'|'right')
    root: str

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "chunk_index": self.chunk_index,
            "chunk_hash": self.chunk_hash,
            "siblings": self.siblings,
            "root": self.root,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MerkleProof":
        """Create from dictionary."""
        return cls(
            chunk_index=data["chunk_index"],
            chunk_hash=data["chunk_hash"],
            siblings=[(s[0], s[1]) for s in data["siblings"]],
            root=data["root"],
        )


@dataclass
class MerkleTree:
    """Merkle Tree for efficient partial verification.

    Attributes:
        root: The root hash of the tree
        leaves: List of leaf hashes
        levels: All levels of the tree (leaves at index 0)
    """

    root: str
    leaves: List[str] = field(default_factory=list)
    levels: List[List[str]] = field(default_factory=list)

    @classmethod
    def from_chunks(cls, chunks: List[str]) -> "MerkleTree":
        """Build Merkle tree from list of string chunks.

        Args:
            chunks: List of strings to include in tree

        Returns:
            MerkleTree instance
        """
        if not chunks:
            return cls(root="", leaves=[], levels=[])

        # Hash all chunks to create leaves
        leaves = [hash_data(chunk) for chunk in chunks]

        # Build tree bottom-up
        levels = [leaves]
        current_level = leaves

        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If odd number of nodes, duplicate the last one
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(hash_pair(left, right))

            levels.append(next_level)
            current_level = next_level

        root = current_level[0] if current_level else ""

        return cls(root=root, leaves=leaves, levels=levels)

    def get_proof(self, chunk_index: int) -> MerkleProof:
        """Get proof for a specific chunk.

        Args:
            chunk_index: Index of the chunk (0-based)

        Returns:
            MerkleProof that can verify the chunk
        """
        if chunk_index < 0 or chunk_index >= len(self.leaves):
            raise ValueError(f"Invalid chunk index: {chunk_index}")

        siblings = []
        index = chunk_index

        for level in self.levels[:-1]:  # Skip root level
            # Determine if we're left or right child
            is_right_child = index % 2 == 1
            sibling_index = index - 1 if is_right_child else index + 1

            # Get sibling hash (or duplicate if at end)
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
            else:
                sibling_hash = level[index]  # Duplicate for odd case

            position = "left" if is_right_child else "right"
            siblings.append((sibling_hash, position))

            # Move to parent index
            index = index // 2

        return MerkleProof(
            chunk_index=chunk_index,
            chunk_hash=self.leaves[chunk_index],
            siblings=siblings,
            root=self.root,
        )

    def verify_chunk(self, chunk: str, chunk_index: int) -> bool:
        """Verify a chunk belongs to this tree.

        Args:
            chunk: The chunk content
            chunk_index: Index of the chunk

        Returns:
            True if chunk is valid
        """
        proof = self.get_proof(chunk_index)
        return verify_proof(chunk, proof, self.root)


def verify_proof(chunk: str, proof: MerkleProof, expected_root: str) -> bool:
    """Verify a Merkle proof.

    Args:
        chunk: The chunk content to verify
        proof: The Merkle proof
        expected_root: Expected root hash

    Returns:
        True if proof is valid
    """
    # Hash the chunk
    current_hash = hash_data(chunk)

    # Check if chunk hash matches
    if current_hash != proof.chunk_hash:
        return False

    # Walk up the tree
    for sibling_hash, position in proof.siblings:
        if position == "left":
            current_hash = hash_pair(sibling_hash, current_hash)
        else:
            current_hash = hash_pair(current_hash, sibling_hash)

    # Check if we reached the expected root
    return current_hash == expected_root
