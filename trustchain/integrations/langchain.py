"""LangChain integration for TrustChain.

Provides adapters to use TrustChain tools with LangChain agents.

Usage:
    from trustchain import TrustChain
    from trustchain.integrations.langchain import to_langchain_tool

    tc = TrustChain()

    @tc.tool("calculator")
    def add(a: int, b: int) -> int:
        '''Add two numbers.'''
        return a + b

    # Convert to LangChain tool
    lc_tool = to_langchain_tool(tc, "calculator")

    # Use with LangChain agent
    from langchain.agents import initialize_agent
    agent = initialize_agent([lc_tool], llm)
"""

from typing import Any, Callable

try:
    from langchain_core.tools import BaseTool

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseTool = None


def _check_langchain():
    """Check if LangChain is installed."""
    if not HAS_LANGCHAIN:
        raise ImportError(
            "LangChain is not installed. Install with: pip install langchain-core"
        )


def _langchain_receipt(signed_response: Any) -> dict:
    """Verifiable receipt: enough fields for a consumer to reconstruct the
    canonical payload and verify the Ed25519 signature offline (no hardcoded
    'verified' flag — verification is the consumer's job)."""
    return {
        "result": signed_response.data,
        "_trustchain": {
            "tool_id": signed_response.tool_id,
            "signature": signed_response.signature,
            "signature_id": signed_response.signature_id,
            "nonce": signed_response.nonce,
            "timestamp": signed_response.timestamp,
            "parent_signature": signed_response.parent_signature,
        },
    }


class TrustChainLangChainTool(BaseTool if HAS_LANGCHAIN else object):
    """LangChain tool wrapper for TrustChain tools.

    Wraps a TrustChain tool to be used with LangChain agents.
    The signature is preserved in the tool's metadata for audit.
    """

    name: str = ""
    description: str = ""

    # TrustChain-specific
    tc_instance: Any = None
    tc_tool_id: str = ""
    tc_original_func: Callable = None

    def __init__(self, tc_instance: "TrustChain", tool_id: str, **kwargs):
        """Initialize LangChain tool wrapper.

        Args:
            tc_instance: TrustChain instance
            tool_id: Tool identifier in TrustChain
        """
        _check_langchain()

        tool_info = tc_instance._tools.get(tool_id)
        if not tool_info:
            raise ValueError(f"Unknown tool: {tool_id}")

        super().__init__(
            name=tool_id, description=tool_info.get("description") or "", **kwargs
        )

        self.tc_instance = tc_instance
        self.tc_tool_id = tool_id
        self.tc_original_func = tool_info["original_func"]

    def _run(self, **kwargs) -> Any:
        """Execute the tool through the signing chain and return signed data + receipt.

        Uses the canonical execution path (_execute_tool_sync) so the call is
        signed AND committed to the audit chain (RFC-003 BF-18) — the previous
        direct _signer.sign() bypassed the chain entirely.
        """
        signed_response = self.tc_instance._execute_tool_sync(
            self.tc_tool_id, self.tc_original_func, (), kwargs
        )
        return _langchain_receipt(signed_response)

    async def _arun(self, **kwargs) -> Any:
        """Async execution through the signing chain (RFC-003 BF-18).

        The prior version fetched the RAW undecorated func from _tools and
        dereferenced .data on its plain return value, crashing every async call.
        """
        import asyncio

        func = self.tc_original_func
        if asyncio.iscoroutinefunction(func):
            signed_response = await self.tc_instance._execute_tool_async(
                self.tc_tool_id, func, (), kwargs
            )
        else:
            signed_response = self.tc_instance._execute_tool_sync(
                self.tc_tool_id, func, (), kwargs
            )
        return _langchain_receipt(signed_response)


def to_langchain_tool(tc: "TrustChain", tool_id: str) -> "BaseTool":
    """Convert a TrustChain tool to a LangChain tool.

    Args:
        tc: TrustChain instance
        tool_id: Tool identifier

    Returns:
        LangChain BaseTool instance
    """
    _check_langchain()
    return TrustChainLangChainTool(tc, tool_id)


def to_langchain_tools(tc: "TrustChain") -> list:
    """Convert all TrustChain tools to LangChain tools.

    Args:
        tc: TrustChain instance

    Returns:
        List of LangChain BaseTool instances
    """
    _check_langchain()
    return [TrustChainLangChainTool(tc, tid) for tid in tc._tools]


# Type hints
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trustchain.v2 import TrustChain
