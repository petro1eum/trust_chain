"""Tests for trustchain/integrations/mcp.py - MCP Server integration."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from trustchain import TrustChain

# Skip tests if mcp not installed
mcp = pytest.importorskip("mcp")

from trustchain.integrations.mcp import (
    HAS_MCP,
    TrustChainMCPServer,
    create_mcp_server,
)


class TestMCPAvailability:
    """Test MCP SDK detection."""

    def test_has_mcp_flag(self):
        assert HAS_MCP is True


class TestTrustChainMCPServer:
    """Test MCP Server wrapper."""

    @pytest.fixture
    def tc(self):
        tc = TrustChain()

        @tc.tool("calculator")
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        @tc.tool("weather")
        def get_weather(city: str) -> dict:
            """Get weather for city."""
            return {"city": city, "temp": 22}

        return tc

    def test_create_server(self, tc):
        server = TrustChainMCPServer(tc, "test-server")

        assert server.name == "test-server"
        assert server.tc is tc

    def test_server_has_mcp_server(self, tc):
        server = TrustChainMCPServer(tc, "test-server")

        assert server.server is not None

    def test_tools_registered(self, tc):
        server = TrustChainMCPServer(tc, "test-server")

        # Check tools are available
        assert len(tc._tools) == 2


class TestCreateMCPServer:
    """Test create_mcp_server convenience function."""

    @pytest.fixture
    def tc(self):
        tc = TrustChain()

        @tc.tool("echo")
        def echo(msg: str) -> str:
            return msg

        return tc

    def test_create_returns_server(self, tc):
        server = create_mcp_server(tc, "my-server")

        assert isinstance(server, TrustChainMCPServer)
        assert server.name == "my-server"

    def test_default_name(self, tc):
        server = create_mcp_server(tc)

        assert server.name is not None
        assert len(server.name) > 0


class TestMCPToolExecution:
    """Test tool execution through MCP server."""

    @pytest.fixture
    def tc(self):
        tc = TrustChain()

        @tc.tool("multiply")
        def multiply(a: int, b: int) -> int:
            """Multiply two numbers."""
            return a * b

        return tc

    def test_tool_callable(self, tc):
        server = TrustChainMCPServer(tc, "test")

        # The @tc.tool decorator creates a wrapper, but _tools stores original
        # For MCP, we sign manually when handling requests
        # Test that the original func is accessible
        original_func = tc._tools["multiply"]["original_func"]
        result = original_func(a=3, b=4)

        # Original function returns raw int
        assert result == 12


class TestMCPSchemaGeneration:
    """Test schema generation for MCP tools."""

    @pytest.fixture
    def tc(self):
        tc = TrustChain()

        @tc.tool("search")
        def search(query: str, limit: int = 10) -> list:
            """Search for items."""
            return []

        return tc

    def test_tool_schema_available(self, tc):
        server = TrustChainMCPServer(tc, "test")

        # Schema should be generatable
        schema = tc.get_tool_schema("search")

        assert schema is not None
        assert schema["function"]["name"] == "search"


class TestMCPSignaturePreservation:
    """Test that signatures are preserved through MCP."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_response_has_signature(self, tc):
        @tc.tool("test")
        def test_func(x: int) -> int:
            return x * 2

        server = TrustChainMCPServer(tc, "test")

        # Call through TrustChain
        result = test_func(5)

        assert result.signature is not None
        assert result.nonce is not None

    def test_signature_is_verifiable(self, tc):
        @tc.tool("test")
        def test_func(x: int) -> int:
            return x * 2

        server = TrustChainMCPServer(tc, "test")
        result = test_func(5)

        assert tc.verify(result) is True
