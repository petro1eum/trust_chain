"""Tests for trustchain/integrations/langchain.py - LangChain integration."""

import pytest
from unittest.mock import MagicMock, patch

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
        # Result is wrapped: {'result': 12} for non-dict returns
        assert result["result"] == {"result": 12}
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
