"""Tests for pytest-trustchain plugin."""

import pytest

from trustchain import SignedResponse, TrustChain

# Import fixtures to make them available
from trustchain.pytest_plugin.fixtures import (
    SignedChainCollector,
    async_tc,
    signed_chain,
    tc,
)


class TestTcFixture:
    """Test tc fixture."""

    def test_tc_fixture_exists(self, tc):
        """Test tc fixture provides TrustChain."""
        assert isinstance(tc, TrustChain)

    def test_tc_can_sign(self, tc):
        """Test tc can sign data."""
        result = tc._signer.sign("test", {"value": 42})
        assert isinstance(result, SignedResponse)
        assert result.tool_id == "test"

    def test_tc_can_verify(self, tc):
        """Test tc can verify signatures."""
        result = tc._signer.sign("test", {"data": "value"})
        assert tc._signer.verify(result) is True


class TestSignedChainCollector:
    """Test SignedChainCollector."""

    def test_create_collector(self):
        """Test collector creation."""
        collector = SignedChainCollector()
        assert len(collector) == 0

    def test_append_response(self):
        """Test appending signed response."""
        collector = SignedChainCollector()
        tc = TrustChain()

        response = tc._signer.sign("test", {})
        collector.append(response)

        assert len(collector) == 1

    def test_append_rejects_non_response(self):
        """Test appending non-SignedResponse raises."""
        collector = SignedChainCollector()

        with pytest.raises(TypeError):
            collector.append({"not": "a response"})

    def test_verify_all(self):
        """Test verify_all method."""
        collector = SignedChainCollector()
        tc = TrustChain()

        collector.append(tc._signer.sign("a", {}))
        collector.append(tc._signer.sign("b", {}))

        assert collector.verify_all(tc) is True

    def test_get_tool_ids(self):
        """Test getting tool IDs from chain."""
        collector = SignedChainCollector()
        tc = TrustChain()

        collector.append(tc._signer.sign("tool_a", {}))
        collector.append(tc._signer.sign("tool_b", {}))
        collector.append(tc._signer.sign("tool_c", {}))

        assert collector.get_tool_ids() == ["tool_a", "tool_b", "tool_c"]

    def test_get_signatures(self):
        """Test getting signatures from chain."""
        collector = SignedChainCollector()
        tc = TrustChain()

        collector.append(tc._signer.sign("a", {}))
        collector.append(tc._signer.sign("b", {}))

        sigs = collector.get_signatures()
        assert len(sigs) == 2
        assert all(len(s) > 10 for s in sigs)

    def test_to_dict_list(self):
        """Test converting to dict list."""
        collector = SignedChainCollector()
        tc = TrustChain()

        collector.append(tc._signer.sign("test", {"value": 1}))

        dicts = collector.to_dict_list()
        assert len(dicts) == 1
        assert dicts[0]["tool_id"] == "test"


class TestSignedChainFixture:
    """Test signed_chain fixture."""

    def test_signed_chain_exists(self, signed_chain):
        """Test signed_chain fixture provides collector."""
        assert isinstance(signed_chain, SignedChainCollector)

    def test_signed_chain_empty(self, signed_chain):
        """Test signed_chain starts empty."""
        assert len(signed_chain) == 0

    def test_signed_chain_usage(self, tc, signed_chain):
        """Test using signed_chain with tc."""
        signed_chain.append(tc._signer.sign("step1", {}))
        signed_chain.append(tc._signer.sign("step2", {}))
        signed_chain.append(tc._signer.sign("step3", {}))

        assert len(signed_chain) == 3
        assert signed_chain.verify_all(tc)


class TestAsyncTcFixture:
    """Test async_tc fixture."""

    @pytest.mark.asyncio
    async def test_async_tc_fixture(self, async_tc):
        """Test async_tc provides AsyncTrustChain."""
        from trustchain.v2.async_core import AsyncTrustChain

        assert isinstance(async_tc, AsyncTrustChain)

    @pytest.mark.asyncio
    async def test_async_tc_can_sign(self, async_tc):
        """Test async_tc can sign."""
        result = await async_tc.sign("test", {"value": 42})

        assert isinstance(result, SignedResponse)
        assert result.tool_id == "test"

    @pytest.mark.asyncio
    async def test_async_tc_can_verify(self, async_tc):
        """Test async_tc can verify."""
        result = await async_tc.sign("test", {})
        is_valid = await async_tc.verify(result)

        assert is_valid is True
