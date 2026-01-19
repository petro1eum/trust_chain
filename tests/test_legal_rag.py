"""Tests for legal RAG demo functionality."""

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.v2.merkle import MerkleTree, verify_proof


class TestLegalRAGConcepts:
    """Test the concepts used in legal_rag_demo.py."""

    def test_merkle_tree_from_chunks(self):
        """Verify Merkle tree can be built from document chunks."""
        pages = [
            "Page 1: Introduction",
            "Page 2: Terms and Conditions",
            "Page 3: Payment Schedule",
            "Page 4: Signatures",
        ]

        tree = MerkleTree.from_chunks(pages)

        assert tree.root is not None
        assert isinstance(tree.root, str)
        assert len(tree.root) > 0

    def test_merkle_proof_verification(self):
        """Verify Merkle proofs work correctly."""
        pages = [f"Page {i}: Content" for i in range(10)]
        tree = MerkleTree.from_chunks(pages)

        # Verify each page
        for idx, page in enumerate(pages):
            proof = tree.get_proof(idx)
            assert verify_proof(page, proof, tree.root)

    def test_merkle_proof_fails_for_tampered_content(self):
        """Verify Merkle proof fails for modified content."""
        pages = ["Page 1", "Page 2", "Page 3"]
        tree = MerkleTree.from_chunks(pages)

        proof = tree.get_proof(1)

        # Original should verify
        assert verify_proof("Page 2", proof, tree.root)

        # Tampered content should fail
        assert not verify_proof("Page 2 MODIFIED", proof, tree.root)

    def test_signed_rag_answer(self):
        """Verify RAG answers can be signed with source references."""
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        pages = ["Contract terms...", "Payment: $100,000", "Termination clause..."]
        tree = MerkleTree.from_chunks(pages)

        @tc.tool("legal_answer")
        def answer_question(question: str, source_pages: list, merkle_root: str):
            return {
                "question": question,
                "answer": "The payment is $100,000",
                "source_pages": source_pages,
                "merkle_root": merkle_root,
            }

        signed = answer_question("What is the payment?", [2], tree.root)  # Page 2

        assert tc.verify(signed)
        assert signed.data["source_pages"] == [2]
        assert signed.data["merkle_root"] == tree.root

    def test_multi_source_verification(self):
        """Verify multiple source pages can be verified."""
        pages = [f"Page {i}" for i in range(100)]
        tree = MerkleTree.from_chunks(pages)

        # Simulate RAG finding multiple relevant pages
        relevant_indices = [12, 47, 83]

        # Verify all sources
        for idx in relevant_indices:
            proof = tree.get_proof(idx)
            assert verify_proof(pages[idx], proof, tree.root)
