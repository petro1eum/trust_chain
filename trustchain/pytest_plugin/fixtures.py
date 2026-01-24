"""pytest fixtures for TrustChain testing.

Provides:
    - tc: Sync TrustChain instance fixture
    - async_tc: Async TrustChain instance fixture
    - signed_chain: Chain collector fixture
"""

from typing import List

import pytest

from trustchain import SignedResponse, TrustChain, TrustChainConfig
from trustchain.v2.async_core import AsyncTrustChain


@pytest.fixture
def tc():
    """Fixture providing a fresh TrustChain instance.

    Example:
        def test_my_tool(tc):
            result = tc.sign("test", {"value": 42})
            assert tc._signer.verify(result)
    """
    return TrustChain()


@pytest.fixture
def tc_config():
    """Fixture providing TrustChain with custom config.

    Override in conftest.py:
        @pytest.fixture
        def tc_config():
            return TrustChainConfig(enable_nonce=False)
    """
    return TrustChainConfig()


@pytest.fixture
def tc_with_config(tc_config):
    """Fixture providing TrustChain with injected config."""
    return TrustChain(tc_config)


@pytest.fixture
async def async_tc():
    """Fixture providing an AsyncTrustChain instance.

    Example:
        @pytest.mark.asyncio
        async def test_async_tool(async_tc):
            result = await async_tc.sign("test", {"data": 1})
            assert await async_tc.verify(result)
    """
    async with AsyncTrustChain() as tc:
        yield tc


@pytest.fixture
def signed_chain():
    """Fixture providing a chain collector.

    Example:
        def test_chain(tc, signed_chain):
            signed_chain.append(tc.sign("step1", {}))
            signed_chain.append(tc.sign("step2", {}))
            assert tc.verify_chain(signed_chain)
    """
    return SignedChainCollector()


class SignedChainCollector(list):
    """List subclass for collecting SignedResponse objects.

    Provides helper methods for chain verification.
    """

    def append(self, item: SignedResponse) -> None:
        """Append a SignedResponse, linking to previous."""
        if not isinstance(item, SignedResponse):
            raise TypeError(f"Expected SignedResponse, got {type(item)}")
        super().append(item)

    def verify_all(self, tc: TrustChain) -> bool:
        """Verify all responses in chain."""
        for response in self:
            if not tc._signer.verify(response):
                return False
        return True

    def get_tool_ids(self) -> List[str]:
        """Get list of tool IDs in chain."""
        return [r.tool_id for r in self]

    def get_signatures(self) -> List[str]:
        """Get list of signatures in chain."""
        return [r.signature for r in self]

    def to_dict_list(self) -> List[dict]:
        """Convert chain to list of dicts."""
        return [r.to_dict() for r in self]
