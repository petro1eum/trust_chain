#!/usr/bin/env python3
"""
Legal RAG Demo with Merkle Verification

Demonstrates cryptographic proof that LLM answers come from specific
document pages. Perfect for LegalTech, FinTech due diligence, and
compliance scenarios.

Usage:
    python legal_rag_demo.py

The demo shows:
1. Document split into pages
2. Merkle tree built from pages
3. Question answered with page references
4. Mathematical proof that answer comes from verified sources
"""

import json
from dataclasses import dataclass

from trustchain import TrustChain, TrustChainConfig
from trustchain.v2.merkle import MerkleTree, verify_proof

# =============================================================================
# Sample Contract Document (simulating PDF extraction)
# =============================================================================

CONTRACT_PAGES = [
    # Page 1 - Cover
    """
    MASTER SERVICES AGREEMENT

    Between: TechCorp Inc. ("Provider")
    And: Enterprise Solutions Ltd. ("Client")

    Effective Date: January 1, 2026
    Contract Number: MSA-2026-001
    """,
    # Page 2 - Definitions
    """
    1. DEFINITIONS

    1.1 "Services" means the software development, consulting, and
    support services described in Exhibit A.

    1.2 "Deliverables" means all work product, code, documentation,
    and materials produced under this Agreement.

    1.3 "Confidential Information" means any non-public information
    disclosed by either party.
    """,
    # Page 3 - Payment Terms
    """
    2. PAYMENT TERMS

    2.1 Fee Structure: Client shall pay Provider the fees set forth
    in Exhibit B, currently set at $150,000 per month.

    2.2 Payment Schedule: Invoices are due within 30 days of receipt.

    2.3 Late Fees: Overdue amounts accrue interest at 1.5% per month.

    2.4 Expenses: Pre-approved expenses reimbursed at cost plus 10%.
    """,
    # Page 4 - Term and Termination
    """
    3. TERM AND TERMINATION

    3.1 Initial Term: This Agreement begins on the Effective Date
    and continues for 24 months unless terminated earlier.

    3.2 Renewal: Agreement auto-renews for successive 12-month terms
    unless either party provides 90 days written notice.

    3.3 Termination for Cause: Either party may terminate upon 30 days
    written notice if the other party materially breaches.
    """,
    # Page 5 - Liability
    """
    4. LIABILITY AND INDEMNIFICATION

    4.1 Limitation of Liability: Neither party's liability shall exceed
    the total fees paid in the 12 months preceding the claim.

    4.2 Exclusions: Neither party is liable for indirect, incidental,
    consequential, or punitive damages.

    4.3 Indemnification: Provider indemnifies Client against third-party
    IP infringement claims arising from Deliverables.
    """,
    # Page 6 - Data Protection
    """
    5. DATA PROTECTION

    5.1 Compliance: Provider shall comply with GDPR, CCPA, and all
    applicable data protection laws.

    5.2 Data Processing: Provider processes Client data only as
    necessary to perform Services.

    5.3 Security: Provider maintains SOC2 Type II certification
    and encrypts all data in transit and at rest.

    5.4 Breach Notification: Provider notifies Client within 72 hours
    of any confirmed data breach.
    """,
    # Page 7 - Intellectual Property
    """
    6. INTELLECTUAL PROPERTY

    6.1 Client Ownership: All Deliverables become Client's property
    upon full payment.

    6.2 Provider Tools: Provider retains ownership of pre-existing
    tools, frameworks, and methodologies.

    6.3 License Grant: Provider grants Client perpetual license to
    use any Provider tools incorporated in Deliverables.
    """,
    # Page 8 - Signatures
    """
    IN WITNESS WHEREOF, the parties have executed this Agreement.

    TECHCORP INC.
    By: _______________________
    Name: John Smith
    Title: CEO
    Date: January 1, 2026

    ENTERPRISE SOLUTIONS LTD.
    By: _______________________
    Name: Jane Doe
    Title: CFO
    Date: January 1, 2026
    """,
]


# =============================================================================
# RAG System with Merkle Verification
# =============================================================================


@dataclass
class VerifiedAnswer:
    """Answer with cryptographic source verification."""

    question: str
    answer: str
    source_pages: list[int]  # 1-indexed for user display
    merkle_root: str
    proofs_valid: list[bool]
    signed_response: object


class LegalRAG:
    """RAG system with cryptographic source verification."""

    def __init__(self, pages: list[str]):
        self.pages = pages
        self.tree = MerkleTree.from_chunks(pages)

        # TrustChain for signing answers
        self.tc = TrustChain(TrustChainConfig(enable_nonce=False))

        # Simple keyword index (in production: use embeddings)
        self.index = self._build_index()

    def _build_index(self) -> dict[str, list[int]]:
        """Build simple keyword -> page index."""
        index: dict[str, set[int]] = {}
        keywords = [
            "payment",
            "fee",
            "invoice",
            "cost",
            "price",
            "termination",
            "cancel",
            "terminate",
            "liability",
            "damages",
            "indemnif",
            "data",
            "gdpr",
            "security",
            "breach",
            "intellectual",
            "property",
            "ownership",
            "confidential",
            "secret",
        ]
        for page_idx, page in enumerate(self.pages):
            page_lower = page.lower()
            for kw in keywords:
                if kw in page_lower:
                    if kw not in index:
                        index[kw] = set()
                    index[kw].add(page_idx)
        return {k: list(v) for k, v in index.items()}

    def _find_relevant_pages(self, question: str) -> list[int]:
        """Find pages relevant to question."""
        question_lower = question.lower()
        relevant = set()
        for keyword, pages in self.index.items():
            if keyword in question_lower:
                relevant.update(pages)
        return sorted(relevant) if relevant else [0]  # Default to cover page

    def ask(self, question: str) -> VerifiedAnswer:
        """Answer question with verified sources."""
        # Find relevant pages
        page_indices = self._find_relevant_pages(question)

        # Generate answer from pages
        context = "\n".join(self.pages[i] for i in page_indices)
        answer = self._generate_answer(question, context, page_indices)

        # Verify each source page
        proofs_valid = []
        for idx in page_indices:
            proof = self.tree.get_proof(idx)
            is_valid = verify_proof(self.pages[idx], proof, self.tree.root)
            proofs_valid.append(is_valid)

        # Sign the complete answer
        @self.tc.tool("legal_answer")
        def sign_answer(q: str, a: str, sources: list) -> dict:
            return {
                "question": q,
                "answer": a,
                "source_pages": sources,
                "merkle_root": self.tree.root,
            }

        signed = sign_answer(question, answer, [i + 1 for i in page_indices])

        return VerifiedAnswer(
            question=question,
            answer=answer,
            source_pages=[i + 1 for i in page_indices],  # 1-indexed
            merkle_root=self.tree.root,
            proofs_valid=proofs_valid,
            signed_response=signed,
        )

    def _generate_answer(
        self, question: str, context: str, page_indices: list[int]
    ) -> str:
        """Generate answer from context (simulated LLM)."""
        # In production, call OpenAI/Anthropic here
        question_lower = question.lower()

        if "payment" in question_lower or "fee" in question_lower:
            return (
                "According to the contract, the monthly fee is $150,000. "
                "Invoices are due within 30 days, with late fees of 1.5% per month."
            )
        elif "terminat" in question_lower or "cancel" in question_lower:
            return (
                "The contract has a 24-month initial term with auto-renewal for "
                "12-month periods. Either party can terminate with 90 days notice, "
                "or 30 days notice for material breach."
            )
        elif "liability" in question_lower or "damage" in question_lower:
            return (
                "Liability is capped at 12 months of fees. Neither party is liable "
                "for indirect, incidental, consequential, or punitive damages."
            )
        elif "data" in question_lower or "gdpr" in question_lower:
            return (
                "Provider must comply with GDPR and CCPA. They maintain SOC2 Type II "
                "certification and must notify Client within 72 hours of any data breach."
            )
        elif "ip" in question_lower or "intellectual" in question_lower:
            return (
                "Deliverables become Client property upon full payment. Provider "
                "retains ownership of pre-existing tools and grants perpetual license."
            )
        else:
            pages_str = ", ".join(str(i + 1) for i in page_indices)
            return f"The answer can be found on page(s) {pages_str} of the contract."


# =============================================================================
# Demo Output
# =============================================================================


def print_verified_answer(va: VerifiedAnswer):
    """Pretty print a verified answer."""
    print("\n" + "=" * 60)
    print(f"Q: {va.question}")
    print("-" * 60)
    print(f"A: {va.answer}")
    print("-" * 60)
    print("SOURCE VERIFICATION:")

    for _i, (page, valid) in enumerate(zip(va.source_pages, va.proofs_valid)):
        status = "[OK]" if valid else "[FAIL]"
        print(f"  Page {page}: {status} Merkle proof verified")

    print(f"\nMerkle Root: {va.merkle_root[:32]}...")
    print(f"Signature: {va.signed_response.signature[:32]}...")
    print("=" * 60)


def main():
    print(
        """
    =====================================================
    LEGAL RAG DEMO: Cryptographic Source Verification
    =====================================================

    This demo shows how TrustChain + Merkle Trees enable
    LLM answers with mathematical proof of source pages.

    Use Cases:
    - M&A Due Diligence
    - Contract Analysis
    - Legal Discovery
    - Compliance Audits
    """
    )

    # Initialize RAG system
    rag = LegalRAG(CONTRACT_PAGES)
    print(f"\nDocument loaded: {len(CONTRACT_PAGES)} pages")
    print(f"Merkle root: {rag.tree.root[:32]}...")

    # Demo questions
    questions = [
        "What are the payment terms and fees?",
        "How can the contract be terminated?",
        "What is the liability cap?",
        "What are the data protection requirements?",
    ]

    print("\n" + "-" * 60)
    print("INTERACTIVE Q&A WITH VERIFIED SOURCES")
    print("-" * 60)

    for q in questions:
        answer = rag.ask(q)
        print_verified_answer(answer)

    # Export verification data
    print("\n" + "=" * 60)
    print("EXPORT FOR AUDIT")
    print("=" * 60)

    verification_data = {
        "document_hash": rag.tree.root,
        "total_pages": len(CONTRACT_PAGES),
        "verification_method": "Merkle Tree + Ed25519",
        "trustchain_version": "2.1.0",
    }
    print(json.dumps(verification_data, indent=2))


if __name__ == "__main__":
    main()
