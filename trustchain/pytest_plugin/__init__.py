"""pytest-trustchain plugin.

Provides fixtures and markers for testing TrustChain-signed tools.

Install:
    pip install trustchain[pytest]

Usage:
    def test_my_tool(tc):  # tc fixture auto-injected
        result = my_tool()
        assert tc.verify(result)

    @pytest.mark.trustchain_verify
    def test_auto_verify():
        '''Auto-verify all SignedResponse returns'''
        return my_tool()
"""

from .fixtures import async_tc, signed_chain, tc
from .plugin import TrustChainPlugin

__all__ = [
    "TrustChainPlugin",
    "tc",
    "async_tc",
    "signed_chain",
]
