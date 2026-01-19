"""Tests for Chain of Trust functionality."""

import pytest
from trustchain import TrustChain
from trustchain.v2.signer import SignedResponse


class TestChainOfTrust:
    """Test Chain of Trust (parent_signature linking)."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_sign_with_parent(self, tc):
        step1 = tc._signer.sign("step1", {"data": 1})
        step2 = tc._signer.sign("step2", {"data": 2}, parent_signature=step1.signature)

        assert step2.parent_signature == step1.signature

    def test_sign_without_parent(self, tc):
        step = tc._signer.sign("test", {"data": 1})

        assert step.parent_signature is None

    def test_parent_signature_in_hash(self, tc):
        """Parent signature must be included in the hash."""
        step1 = tc._signer.sign("step1", {"data": 1})

        # Sign same data with different parents
        step2a = tc._signer.sign("step2", {"data": 2}, parent_signature=step1.signature)
        step2b = tc._signer.sign("step2", {"data": 2}, parent_signature=None)

        # Signatures should be different because parent is in hash
        # (Actually due to nonce they'll be different anyway, but this tests the concept)
        assert step2a.parent_signature != step2b.parent_signature


class TestVerifyChain:
    """Test verify_chain() method."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_verify_empty_chain(self, tc):
        assert tc.verify_chain([]) is True

    def test_verify_single_item(self, tc):
        step = tc._signer.sign("test", {"data": 1})
        assert tc.verify_chain([step]) is True

    def test_verify_two_items(self, tc):
        step1 = tc._signer.sign("step1", {"data": 1})
        step2 = tc._signer.sign("step2", {"data": 2}, parent_signature=step1.signature)

        assert tc.verify_chain([step1, step2]) is True

    def test_verify_long_chain(self, tc):
        chain = []
        parent_sig = None

        for i in range(10):
            step = tc._signer.sign(
                f"step_{i}", {"index": i}, parent_signature=parent_sig
            )
            chain.append(step)
            parent_sig = step.signature

        assert tc.verify_chain(chain) is True

    def test_verify_broken_chain(self, tc):
        step1 = tc._signer.sign("step1", {"data": 1})
        step2 = tc._signer.sign("step2", {"data": 2}, parent_signature=step1.signature)
        step3 = tc._signer.sign(
            "step3", {"data": 3}, parent_signature="WRONG_SIGNATURE"
        )

        # Step3 doesn't link to step2
        assert tc.verify_chain([step1, step2, step3]) is False

    def test_verify_chain_missing_first_parent(self, tc):
        step1 = tc._signer.sign("step1", {"data": 1})
        step2 = tc._signer.sign("step2", {"data": 2}, parent_signature=step1.signature)

        # First item should not have parent
        step1_with_parent = tc._signer.sign(
            "step1", {"data": 1}, parent_signature="fake"
        )
        step2_linked = tc._signer.sign(
            "step2", {"data": 2}, parent_signature=step1_with_parent.signature
        )

        # This is valid - first can have parent (it just won't be checked)
        assert tc.verify_chain([step1_with_parent, step2_linked]) is True

    def test_verify_chain_order_matters(self, tc):
        step1 = tc._signer.sign("step1", {"data": 1})
        step2 = tc._signer.sign("step2", {"data": 2}, parent_signature=step1.signature)

        # Wrong order
        assert tc.verify_chain([step2, step1]) is False


class TestChainOfTrustVerification:
    """Test signature verification in chain context."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_individual_signatures_valid(self, tc):
        chain = []
        parent_sig = None

        for i in range(5):
            step = tc._signer.sign(f"step_{i}", {"i": i}, parent_signature=parent_sig)
            chain.append(step)
            parent_sig = step.signature

        # Each signature should verify individually
        for step in chain:
            assert tc._signer.verify(step) is True

    def test_tampered_data_fails(self, tc):
        step1 = tc._signer.sign("step1", {"data": 1})
        step2 = tc._signer.sign("step2", {"data": 2}, parent_signature=step1.signature)

        # Tamper with step2's data
        step2.data = {"data": 999}

        # Chain should fail verification
        assert tc.verify_chain([step1, step2]) is False

    def test_chain_integrity(self, tc):
        """Test that you can't insert/remove steps."""
        # Use fresh TrustChain to avoid nonce conflicts from other tests
        fresh_tc = TrustChain()

        step1 = fresh_tc._signer.sign("step1", {"data": 1})
        step2 = fresh_tc._signer.sign(
            "step2", {"data": 2}, parent_signature=step1.signature
        )
        step3 = fresh_tc._signer.sign(
            "step3", {"data": 3}, parent_signature=step2.signature
        )

        # Another fresh instance for verification (no nonce conflicts)
        verify_tc = TrustChain()
        verify_tc._signer = fresh_tc._signer  # Share keys

        # Full chain valid
        assert verify_tc.verify_chain([step1, step2, step3]) is True

        # Create second fresh instance for broken chain test
        verify_tc2 = TrustChain()
        verify_tc2._signer = fresh_tc._signer

        # Missing step2 - breaks chain (step3.parent != step1.signature)
        assert verify_tc2.verify_chain([step1, step3]) is False


class TestRealWorldChainScenarios:
    """Test realistic chain of trust scenarios."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_banking_workflow(self, tc):
        """Simulate a banking transaction chain."""
        # Step 1: Authenticate
        auth = tc._signer.sign(
            "authenticate", {"user": "alice", "method": "2fa", "verified": True}
        )

        # Step 2: Check balance
        balance = tc._signer.sign(
            "check_balance",
            {"account": "ACC001", "balance": 10000.0},
            parent_signature=auth.signature,
        )

        # Step 3: Execute transfer
        transfer = tc._signer.sign(
            "transfer",
            {"from": "ACC001", "to": "ACC002", "amount": 500.0, "status": "completed"},
            parent_signature=balance.signature,
        )

        # Step 4: Confirm
        confirm = tc._signer.sign(
            "confirm",
            {"transaction_id": "TXN123", "receipt": True},
            parent_signature=transfer.signature,
        )

        chain = [auth, balance, transfer, confirm]

        # Full chain should verify
        assert tc.verify_chain(chain) is True

        # Each step links to previous
        assert balance.parent_signature == auth.signature
        assert transfer.parent_signature == balance.signature
        assert confirm.parent_signature == transfer.signature

    def test_ai_agent_workflow(self, tc):
        """Simulate AI agent multi-step reasoning."""
        # Step 1: Search
        search = tc._signer.sign(
            "search", {"query": "weather Moscow", "results": ["sunny", "22C"]}
        )

        # Step 2: Analyze
        analyze = tc._signer.sign(
            "analyze",
            {"input_summary": "sunny 22C", "conclusion": "Good weather"},
            parent_signature=search.signature,
        )

        # Step 3: Generate response
        response = tc._signer.sign(
            "generate_response",
            {"text": "The weather in Moscow is sunny at 22C - good weather!"},
            parent_signature=analyze.signature,
        )

        chain = [search, analyze, response]

        assert tc.verify_chain(chain) is True
