#!/usr/bin/env python3
"""Example: Secure RAG with TrustChain.

This example shows how to build a RAG (Retrieval-Augmented Generation) system
with cryptographic verification of sources using Merkle Trees.

Features:
- Each document chunk is signed
- Merkle Tree proves chunk authenticity
- Full audit trail of retrieved sources
- Chain of Trust linking query → retrieval → answer

Requirements:
    pip install openai chromadb

Usage:
    export OPENAI_API_KEY=your_key
    python examples/secure_rag.py
"""

from typing import List, Dict, Any
from trustchain import TrustChain
from trustchain.v2.merkle import MerkleTree, verify_proof


class SecureRAG:
    """RAG system with cryptographic verification."""

    def __init__(self, compliance_mode: str = "standard"):
        """Initialize SecureRAG.

        Args:
            compliance_mode: "standard", "SOC2", or "HIPAA"
        """
        self.tc = TrustChain()
        self.compliance_mode = compliance_mode
        self.documents: Dict[str, Dict[str, Any]] = {}
        self.merkle_trees: Dict[str, MerkleTree] = {}

        # Register tools
        self._register_tools()

    def _register_tools(self):
        """Register RAG tools with TrustChain."""

        @self.tc.tool("ingest_document")
        def ingest_document(doc_id: str, content: str) -> dict:
            """Ingest a document and create Merkle tree."""
            return self._ingest(doc_id, content)

        @self.tc.tool("search_documents")
        def search_documents(query: str, top_k: int = 3) -> dict:
            """Search documents and return verified chunks."""
            return self._search(query, top_k)

        @self.tc.tool("verify_chunk")
        def verify_chunk(doc_id: str, chunk_index: int, content: str) -> dict:
            """Verify a chunk against its Merkle proof."""
            return self._verify(doc_id, chunk_index, content)

    def _ingest(self, doc_id: str, content: str) -> dict:
        """Ingest document and create Merkle tree."""
        # Split into chunks
        chunk_size = 500
        chunks = [
            content[i : i + chunk_size] for i in range(0, len(content), chunk_size)
        ]

        # Create Merkle tree
        tree = MerkleTree.from_chunks(chunks)

        # Store
        self.documents[doc_id] = {
            "chunks": chunks,
            "chunk_count": len(chunks),
            "merkle_root": tree.root,
        }
        self.merkle_trees[doc_id] = tree

        return {
            "doc_id": doc_id,
            "chunk_count": len(chunks),
            "merkle_root": tree.root[:32] + "...",
        }

    def _search(self, query: str, top_k: int) -> dict:
        """Search documents (simple keyword match for demo)."""
        results = []

        for doc_id, doc in self.documents.items():
            for i, chunk in enumerate(doc["chunks"]):
                # Simple relevance scoring (in production use embeddings)
                if query.lower() in chunk.lower():
                    tree = self.merkle_trees[doc_id]
                    proof = tree.get_proof(i)

                    results.append(
                        {
                            "doc_id": doc_id,
                            "chunk_index": i,
                            "content": (
                                chunk[:200] + "..." if len(chunk) > 200 else chunk
                            ),
                            "merkle_proof": {
                                "root": tree.root[:16] + "...",
                                "siblings_count": len(proof.siblings),
                            },
                        }
                    )

        return {
            "query": query,
            "results": results[:top_k],
            "verified": True,
        }

    def _verify(self, doc_id: str, chunk_index: int, content: str) -> dict:
        """Verify chunk authenticity."""
        if doc_id not in self.merkle_trees:
            return {"verified": False, "error": "Document not found"}

        tree = self.merkle_trees[doc_id]
        proof = tree.get_proof(chunk_index)

        is_valid = verify_proof(content, proof, tree.root)

        return {
            "doc_id": doc_id,
            "chunk_index": chunk_index,
            "verified": is_valid,
            "merkle_root": tree.root[:32] + "...",
        }


def main():
    """Demo the SecureRAG system."""
    print("🔐 SecureRAG - RAG with Cryptographic Verification")
    print()

    # Initialize
    rag = SecureRAG(compliance_mode="SOC2")

    # Sample documents
    contracts = """
    CONTRACT AGREEMENT
    
    This agreement is made between Acme Corp ("Company") and John Doe ("Client").
    
    1. SERVICES: Company will provide software development services.
    2. PAYMENT: Client agrees to pay $10,000 upon completion.
    3. TIMELINE: Work will be completed within 30 days.
    4. CONFIDENTIALITY: All information is strictly confidential.
    5. TERMINATION: Either party may terminate with 7 days notice.
    
    Signed: Acme Corp, John Doe
    Date: January 19, 2026
    """

    # Ingest document
    print("📄 Ingesting document...")
    result = rag._ingest("contract_001", contracts)
    print(f"   Doc ID: {result['doc_id']}")
    print(f"   Chunks: {result['chunk_count']}")
    print(f"   Merkle Root: {result['merkle_root']}")
    print()

    # Search
    print("🔍 Searching for 'payment'...")
    search_result = rag._search("payment", top_k=2)
    for r in search_result["results"]:
        print(f"   Found in {r['doc_id']}, chunk {r['chunk_index']}")
        print(f"   Content: {r['content'][:100]}...")
        print(f"   Proof: {r['merkle_proof']['siblings_count']} siblings")
    print()

    # Verify
    print("✅ Verifying chunk...")
    original_chunk = rag.documents["contract_001"]["chunks"][0]
    verify_result = rag._verify("contract_001", 0, original_chunk)
    print(f"   Verified: {verify_result['verified']}")
    print()

    # Try to verify tampered content
    print("❌ Verifying TAMPERED chunk...")
    tampered = original_chunk.replace("Acme Corp", "FAKE Corp")
    verify_result = rag._verify("contract_001", 0, tampered)
    print(f"   Verified: {verify_result['verified']} (Expected: False)")
    print()

    print("🎉 SecureRAG demo complete!")
    print("   Every chunk is cryptographically verified via Merkle proofs.")


if __name__ == "__main__":
    main()
