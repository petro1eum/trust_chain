"""Tests for trustchain/v2/merkle.py - Merkle Tree implementation."""

import pytest
import hashlib

from trustchain.v2.merkle import (
    MerkleTree,
    MerkleProof,
    verify_proof,
    hash_data,
    hash_pair,
)


class TestHashFunctions:
    """Test hash utility functions."""

    def test_hash_data(self):
        result = hash_data("hello")

        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex digest

    def test_hash_data_deterministic(self):
        assert hash_data("test") == hash_data("test")
        assert hash_data("a") != hash_data("b")

    def test_hash_pair(self):
        result = hash_pair("abc", "def")

        assert isinstance(result, str)
        assert len(result) == 64

    def test_hash_pair_order_matters(self):
        assert hash_pair("a", "b") != hash_pair("b", "a")


class TestMerkleTreeConstruction:
    """Test Merkle tree construction."""

    def test_from_single_chunk(self):
        tree = MerkleTree.from_chunks(["hello"])

        assert tree.root is not None
        assert len(tree.leaves) == 1
        assert tree.root == tree.leaves[0]

    def test_from_two_chunks(self):
        tree = MerkleTree.from_chunks(["a", "b"])

        assert len(tree.leaves) == 2
        assert tree.root != tree.leaves[0]
        assert tree.root != tree.leaves[1]

    def test_from_multiple_chunks(self):
        chunks = [f"chunk_{i}" for i in range(10)]
        tree = MerkleTree.from_chunks(chunks)

        assert len(tree.leaves) == 10
        assert tree.root is not None

    def test_power_of_two_chunks(self):
        tree = MerkleTree.from_chunks(["a", "b", "c", "d"])

        # For 4 leaves: 2 levels above leaves
        assert len(tree.levels) == 3  # leaves, intermediate, root
        assert len(tree.levels[0]) == 4  # leaves
        assert len(tree.levels[1]) == 2  # intermediate
        assert len(tree.levels[2]) == 1  # root

    def test_odd_number_chunks(self):
        tree = MerkleTree.from_chunks(["a", "b", "c"])

        # Should handle odd number by duplicating last
        assert tree.root is not None
        assert len(tree.leaves) == 3

    def test_empty_chunks(self):
        tree = MerkleTree.from_chunks([])

        assert tree.root == ""
        assert len(tree.leaves) == 0

    def test_large_tree(self):
        chunks = [f"page_{i}" for i in range(100)]
        tree = MerkleTree.from_chunks(chunks)

        assert len(tree.leaves) == 100
        # 100 leaves = 7 levels (ceil(log2(100)) + 1)
        assert len(tree.levels) >= 7


class TestMerkleProof:
    """Test Merkle proof generation."""

    def test_get_proof_first_leaf(self):
        tree = MerkleTree.from_chunks(["a", "b", "c", "d"])
        proof = tree.get_proof(0)

        assert isinstance(proof, MerkleProof)
        assert proof.chunk_hash == hash_data("a")
        assert proof.chunk_index == 0
        assert len(proof.siblings) > 0

    def test_get_proof_last_leaf(self):
        tree = MerkleTree.from_chunks(["a", "b", "c", "d"])
        proof = tree.get_proof(3)

        assert proof.chunk_index == 3
        assert proof.chunk_hash == hash_data("d")

    def test_get_proof_middle_leaf(self):
        tree = MerkleTree.from_chunks(["a", "b", "c", "d"])
        proof = tree.get_proof(1)

        assert proof.chunk_index == 1

    def test_proof_siblings_structure(self):
        tree = MerkleTree.from_chunks(["a", "b", "c", "d"])
        proof = tree.get_proof(0)

        # Each sibling is (hash, position)
        for sibling_hash, position in proof.siblings:
            assert isinstance(sibling_hash, str)
            assert position in ("left", "right")

    def test_proof_size(self):
        # For n leaves, proof has log2(n) siblings
        tree = MerkleTree.from_chunks([f"c_{i}" for i in range(64)])
        proof = tree.get_proof(0)

        # 64 = 2^6, so should have ~6 siblings
        assert len(proof.siblings) == 6

    def test_invalid_index(self):
        tree = MerkleTree.from_chunks(["a", "b"])

        with pytest.raises(ValueError):  # Changed from IndexError
            tree.get_proof(5)


class TestVerifyProof:
    """Test Merkle proof verification."""

    def test_verify_valid_proof(self):
        chunks = ["a", "b", "c", "d"]
        tree = MerkleTree.from_chunks(chunks)

        for i, chunk in enumerate(chunks):
            proof = tree.get_proof(i)
            assert verify_proof(chunk, proof, tree.root) is True

    def test_verify_invalid_content(self):
        tree = MerkleTree.from_chunks(["a", "b", "c", "d"])
        proof = tree.get_proof(0)

        # Try to verify with wrong content
        assert verify_proof("WRONG", proof, tree.root) is False

    def test_verify_invalid_root(self):
        tree = MerkleTree.from_chunks(["a", "b", "c", "d"])
        proof = tree.get_proof(0)

        # Try with wrong root
        assert verify_proof("a", proof, "wrong_root_hash") is False

    def test_verify_tampered_proof(self):
        tree = MerkleTree.from_chunks(["a", "b", "c", "d"])
        proof = tree.get_proof(0)

        # Tamper with sibling hash
        tampered_siblings = [("tampered_hash", "right")] + proof.siblings[1:]
        tampered_proof = MerkleProof(
            chunk_index=0,
            chunk_hash=proof.chunk_hash,
            siblings=tampered_siblings,
            root=tree.root,  # Include root
        )

        assert verify_proof("a", tampered_proof, tree.root) is False

    def test_verify_large_tree(self):
        chunks = [f"document_page_{i}" for i in range(100)]
        tree = MerkleTree.from_chunks(chunks)

        # Verify random pages
        for i in [0, 42, 73, 99]:
            proof = tree.get_proof(i)
            assert verify_proof(chunks[i], proof, tree.root) is True
            assert verify_proof("tampered", proof, tree.root) is False


class TestMerkleTreeDeterminism:
    """Test that Merkle tree is deterministic."""

    def test_same_input_same_root(self):
        chunks = ["hello", "world", "foo", "bar"]

        tree1 = MerkleTree.from_chunks(chunks)
        tree2 = MerkleTree.from_chunks(chunks)

        assert tree1.root == tree2.root

    def test_different_input_different_root(self):
        tree1 = MerkleTree.from_chunks(["a", "b"])
        tree2 = MerkleTree.from_chunks(["a", "c"])

        assert tree1.root != tree2.root

    def test_order_matters(self):
        tree1 = MerkleTree.from_chunks(["a", "b"])
        tree2 = MerkleTree.from_chunks(["b", "a"])

        assert tree1.root != tree2.root


class TestRealWorldScenarios:
    """Test realistic use cases."""

    def test_document_pages(self):
        """Simulate verifying pages of a PDF."""
        pages = [
            "Chapter 1: Introduction...",
            "Chapter 2: Methods...",
            "Chapter 3: Results...",
            "Chapter 4: Discussion...",
            "References...",
        ]

        tree = MerkleTree.from_chunks(pages)

        # Verify chapter 3 only (index 2)
        proof = tree.get_proof(2)
        assert verify_proof(pages[2], proof, tree.root) is True

    def test_rag_chunks(self):
        """Simulate RAG document verification."""
        chunks = [
            "The company was founded in 2010.",
            "Revenue grew by 20% last year.",
            "The CEO announced new products.",
        ]

        tree = MerkleTree.from_chunks(chunks)
        root_to_sign = tree.root

        # Later: verify a retrieved chunk
        retrieved = "Revenue grew by 20% last year."
        proof = tree.get_proof(1)

        assert verify_proof(retrieved, proof, root_to_sign) is True

    def test_proof_is_compact(self):
        """Verify proof size is logarithmic."""
        # 1000 pages
        pages = [f"Page {i}: content..." for i in range(1000)]
        tree = MerkleTree.from_chunks(pages)
        proof = tree.get_proof(500)

        # log2(1000) ~ 10, so proof should have ~10 siblings
        assert len(proof.siblings) <= 11

        # This is much smaller than transmitting all 1000 pages
        assert len(proof.siblings) < len(pages) / 50
