"""Tests for trustchain/integrations/langchain.py - LangChain integration."""

from unittest.mock import MagicMock, patch

import pytest

from trustchain import TrustChain

# Skip tests if langchain not installed
pytest.importorskip("langchain_core")

from trustchain.integrations.langchain import (
    TrustChainLangChainTool,
    to_langchain_tool,
    to_langchain_tools,
)


class TestTrustChainLangChainTool:
    """Test LangChain tool wrapper."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_create_tool(self, tc):
        @tc.tool("calculator")
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        lc_tool = TrustChainLangChainTool(tc, "calculator")

        assert lc_tool.name == "calculator"
        assert "Add" in lc_tool.description or "add" in lc_tool.description.lower()

    def test_tool_execution(self, tc):
        @tc.tool("multiply")
        def multiply(a: int, b: int) -> int:
            """Multiply two numbers."""
            return a * b

        lc_tool = TrustChainLangChainTool(tc, "multiply")

        result = lc_tool._run(a=3, b=4)

        # Result should be dict with 'result' and '_trustchain'
        assert isinstance(result, dict)
        # signed.data is the tool's actual return (12), signed via the chain path
        assert result["result"] == 12
        assert "_trustchain" in result
        assert "signature" in result["_trustchain"]

    def test_tool_preserves_signature(self, tc):
        @tc.tool("test")
        def test_func(x: int) -> int:
            return x * 2

        lc_tool = TrustChainLangChainTool(tc, "test")

        # Execute
        result = lc_tool._run(x=5)

        # Should have signature in _trustchain
        assert "_trustchain" in result
        assert result["_trustchain"]["signature"] is not None


def test_langchain_run_commits_to_chain_and_is_verifiable():
    from trustchain import TrustChain, TrustChainConfig
    from trustchain.integrations.langchain import TrustChainLangChainTool

    tc = TrustChain(
        TrustChainConfig(enable_chain=True, enable_pki=False, chain_storage="memory")
    )

    @tc.tool("adder")
    def add(a: int, b: int) -> int:
        return a + b

    before = tc.chain.length
    lc = TrustChainLangChainTool(tc, "adder")
    result = lc._run(a=2, b=5)
    assert result["result"] == 7
    tr = result["_trustchain"]
    assert tr["signature"] and tr["signature_id"] and tr["timestamp"] is not None
    # BF-18: the sync path now commits to the audit chain (was bypassed before).
    assert tc.chain.length == before + 1


def test_langchain_arun_executes_without_crashing():
    import asyncio

    from trustchain import TrustChain, TrustChainConfig
    from trustchain.integrations.langchain import TrustChainLangChainTool

    tc = TrustChain(
        TrustChainConfig(enable_chain=True, enable_pki=False, chain_storage="memory")
    )

    @tc.tool("aget")
    async def aget(x: int) -> dict:
        return {"x": x}

    lc = TrustChainLangChainTool(tc, "aget")
    result = asyncio.run(lc._arun(x=9))
    assert result["result"] == {"x": 9}
    assert result["_trustchain"]["signature"]


class TestToLangchainTool:
    """Test to_langchain_tool function."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_convert_single_tool(self, tc):
        @tc.tool("weather")
        def get_weather(city: str) -> dict:
            """Get weather for city."""
            return {"city": city, "temp": 20}

        lc_tool = to_langchain_tool(tc, "weather")

        assert lc_tool is not None
        assert lc_tool.name == "weather"
        assert (
            "weather" in lc_tool.description.lower()
            or "city" in lc_tool.description.lower()
        )

    def test_convert_nonexistent_tool(self, tc):
        with pytest.raises(ValueError):  # Changed from KeyError to ValueError
            to_langchain_tool(tc, "nonexistent")


class TestToLangchainTools:
    """Test to_langchain_tools function."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_convert_all_tools(self, tc):
        @tc.tool("add")
        def add(a: int, b: int) -> int:
            return a + b

        @tc.tool("sub")
        def subtract(a: int, b: int) -> int:
            return a - b

        @tc.tool("mul")
        def multiply(a: int, b: int) -> int:
            return a * b

        tools = to_langchain_tools(tc)

        assert len(tools) == 3
        names = [t.name for t in tools]
        assert "add" in names
        assert "sub" in names
        assert "mul" in names

    def test_empty_trustchain(self, tc):
        tools = to_langchain_tools(tc)
        assert len(tools) == 0

    def test_tools_are_executable(self, tc):
        @tc.tool("echo")
        def echo(msg: str) -> str:
            return msg

        tools = to_langchain_tools(tc)
        echo_tool = tools[0]

        result = echo_tool._run(msg="hello")
        # Returns dict with 'result' key
        assert "hello" in str(result["result"])


class TestLangChainCompatibility:
    """Test compatibility with LangChain patterns."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_tool_has_required_attributes(self, tc):
        @tc.tool("test")
        def test_func(x: int) -> int:
            return x

        tools = to_langchain_tools(tc)
        tool = tools[0]

        # Required by LangChain
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert hasattr(tool, "_run")

    def test_tool_input_schema(self, tc):
        @tc.tool("search")
        def search(query: str, limit: int = 10) -> list:
            """Search for items."""
            return []

        tools = to_langchain_tools(tc)
        tool = tools[0]

        # Should have args_schema (Pydantic model)
        assert hasattr(tool, "args_schema") or hasattr(tool, "args")
