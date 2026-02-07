"""End-to-end tests for complete TrustChain workflows."""

import tempfile
from pathlib import Path

import pytest

from trustchain import TrustChain
from trustchain.v2.events import TrustEvent
from trustchain.v2.merkle import MerkleTree, verify_proof


class TestE2EBankingWorkflow:
    """E2E test: Complete banking transaction workflow."""

    def test_complete_transaction_flow(self):
        tc = TrustChain()
        chain = []

        # Step 1: User authentication
        @tc.tool("auth")
        def authenticate(user_id: str, method: str) -> dict:
            return {"user_id": user_id, "authenticated": True, "method": method}

        auth_result = authenticate("alice@bank.com", "2fa")
        chain.append(auth_result)

        # Step 2: Check balance with chain link
        balance_result = tc._signer.sign(
            "check_balance",
            {"account": "ACC001", "balance": 10000.00},
            parent_signature=auth_result.signature,
        )
        chain.append(balance_result)

        # Step 3: Execute transfer
        transfer_result = tc._signer.sign(
            "transfer",
            {"from": "ACC001", "to": "ACC002", "amount": 500.00},
            parent_signature=balance_result.signature,
        )
        chain.append(transfer_result)

        # Step 4: Confirmation
        confirm_result = tc._signer.sign(
            "confirm",
            {"transaction_id": "TXN-2026-001", "status": "completed"},
            parent_signature=transfer_result.signature,
        )
        chain.append(confirm_result)

        # Verify entire chain
        assert tc.verify_chain(chain) is True

        # Verify each step individually
        for step in chain:
            assert tc._signer.verify(step) is True

        # Verify chain links
        assert balance_result.parent_signature == auth_result.signature
        assert transfer_result.parent_signature == balance_result.signature
        assert confirm_result.parent_signature == transfer_result.signature


class TestE2ERAGWorkflow:
    """E2E test: RAG with document verification."""

    def test_rag_with_merkle_verification(self):
        tc = TrustChain()

        # Simulate document ingestion
        document = """
        Chapter 1: Company Overview
        Acme Corp was founded in 2010 with $1M seed funding.

        Chapter 2: Financial Summary
        Revenue grew 25% year-over-year reaching $50M.

        Chapter 3: Projections
        We expect 30% growth in the next fiscal year.
        """

        # Split into chunks
        chunks = [line.strip() for line in document.split("\n") if line.strip()]

        # Build Merkle tree
        tree = MerkleTree.from_chunks(chunks)

        # Sign the root
        doc_signed = tc._signer.sign(
            "document_ingested",
            {
                "doc_id": "annual_report_2025",
                "merkle_root": tree.root,
                "chunk_count": len(chunks),
            },
        )

        # Simulate retrieval query
        query_result = tc._signer.sign(
            "rag_query",
            {"query": "revenue growth", "chunk_index": 4},
            parent_signature=doc_signed.signature,
        )

        # Verify retrieved chunk
        retrieved_chunk = chunks[4]  # "Revenue grew 25%..."
        proof = tree.get_proof(4)

        assert verify_proof(retrieved_chunk, proof, tree.root) is True

        # Generate response with chain link
        response = tc._signer.sign(
            "generate_response",
            {"text": "Revenue grew 25% YoY to $50M", "source_verified": True},
            parent_signature=query_result.signature,
        )

        # Verify complete chain
        chain = [doc_signed, query_result, response]
        assert tc.verify_chain(chain) is True


class TestE2EMultiTenantWorkflow:
    """E2E test: Multi-tenant SaaS scenario."""

    def test_isolated_tenants(self):
        from trustchain.v2.tenants import TenantManager

        with tempfile.TemporaryDirectory() as temp_dir:
            manager = TenantManager(key_storage_dir=temp_dir)

            # Tenant A: E-commerce
            tc_ecommerce = manager.get_or_create("ecommerce_tenant")

            @tc_ecommerce.tool("process_order")
            def process_order(order_id: str, amount: float) -> dict:
                return {"order_id": order_id, "amount": amount, "status": "confirmed"}

            order_result = process_order("ORD-001", 99.99)

            # Tenant B: Healthcare
            tc_healthcare = manager.get_or_create("healthcare_tenant")

            @tc_healthcare.tool("patient_record")
            def get_patient(patient_id: str) -> dict:
                return {"patient_id": patient_id, "name": "John Doe"}

            patient_result = get_patient("PAT-001")

            # Each tenant can verify their own signatures
            assert tc_ecommerce._signer.verify(order_result) is True
            assert tc_healthcare._signer.verify(patient_result) is True

            # Cross-tenant verification should fail
            assert tc_ecommerce._signer.verify(patient_result) is False
            assert tc_healthcare._signer.verify(order_result) is False


class TestE2ECloudEventsWorkflow:
    """E2E test: CloudEvents integration."""

    def test_event_emission_and_processing(self):
        tc = TrustChain()
        events = []

        # Simulate multiple tool calls
        operations = [
            ("search", {"query": "weather"}),
            ("fetch", {"url": "api.weather.com"}),
            ("parse", {"format": "json"}),
        ]

        parent_sig = None
        chain_id = "workflow-001"

        for tool_id, data in operations:
            signed = tc._signer.sign(tool_id, data, parent_signature=parent_sig)

            # Create CloudEvent
            event = TrustEvent.from_signed_response(
                signed, source=f"/agent/weather-bot/tool/{tool_id}", chain_id=chain_id
            )
            events.append(event)

            parent_sig = signed.signature

        # Verify all events have correct format
        for event in events:
            assert event.specversion == "1.0"
            assert event.type == "ai.tool.response.v1"
            assert event.trustchain_signature is not None

        # Verify chain IDs match
        for event in events:
            assert event.trustchain_chain_id == chain_id

        # Verify events can be serialized
        for event in events:
            json_str = event.to_json()
            assert len(json_str) > 0


class TestE2EErrorRecovery:
    """E2E test: Error handling and recovery."""

    def test_chain_continues_after_error(self):
        tc = TrustChain()
        chain = []

        # Step 1: Success
        step1 = tc._signer.sign("step1", {"status": "ok"})
        chain.append(step1)

        # Step 2: Simulated failure (would be caught in real code)
        try:
            raise ValueError("Simulated API error")
        except ValueError:
            error_step = tc._signer.sign(
                "step2_error",
                {"status": "error", "message": "API unavailable"},
                parent_signature=step1.signature,
            )
            chain.append(error_step)

        # Step 3: Retry success
        step3 = tc._signer.sign(
            "step2_retry",
            {"status": "ok", "attempt": 2},
            parent_signature=error_step.signature,
        )
        chain.append(step3)

        # Chain should still verify
        assert tc.verify_chain(chain) is True

        # Error is recorded in chain
        assert chain[1].data["status"] == "error"
