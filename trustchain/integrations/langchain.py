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
        """Execute the tool and return signed response data.

        The signature is stored in the response metadata.
        """
        # Call the original function
        original_func = self.tc_original_func
        result = original_func(**kwargs)

        # Sign the result
        signed_response = self.tc_instance._signer.sign(
            self.tc_tool_id, result if isinstance(result, dict) else {"result": result}
        )

        # Return the data, but include signature in metadata
        return {
            "result": signed_response.data,
            "_trustchain": {
                "signature": signed_response.signature,
                "signature_id": signed_response.signature_id,
                "nonce": signed_response.nonce,
                "verified": True,
            },
        }

    async def _arun(self, **kwargs) -> Any:
        """Async execution."""
        # For async tools, call the async wrapper
        wrapped_func = self.tc_instance._tools[self.tc_tool_id]["func"]

        import asyncio

        if asyncio.iscoroutinefunction(wrapped_func):
            signed_response = await wrapped_func(**kwargs)
        else:
            signed_response = wrapped_func(**kwargs)

        return {
            "result": signed_response.data,
            "_trustchain": {
                "signature": signed_response.signature,
                "signature_id": signed_response.signature_id,
                "nonce": signed_response.nonce,
                "verified": True,
            },
        }


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
