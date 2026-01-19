"""Model Context Protocol (MCP) Server for TrustChain.

Exposes TrustChain tools as an MCP server that can be used by
Claude Desktop, Cursor, and other MCP-compatible clients.

Usage:
    from trustchain.v2 import TrustChain
    from trustchain.integrations.mcp import serve_mcp

    tc = TrustChain()

    @tc.tool("weather")
    def get_weather(city: str) -> dict:
        return {"temp": 22, "city": city}

    # Start MCP server (stdio mode for Claude Desktop)
    serve_mcp(tc)

For Claude Desktop, add to ~/Library/Application Support/Claude/claude_desktop_config.json:
{
  "mcpServers": {
    "trustchain": {
      "command": "python",
      "args": ["-m", "trustchain.integrations.mcp", "--config", "path/to/config.py"]
    }
  }
}
"""

import asyncio
import json
import sys
from typing import Any, Callable, Dict, List, Optional

# Check for MCP SDK
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent

    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    Server = None


def _check_mcp():
    """Check if MCP SDK is installed."""
    if not HAS_MCP:
        raise ImportError("MCP SDK is not installed. Install with: pip install mcp")


class TrustChainMCPServer:
    """MCP Server wrapper for TrustChain.

    Exposes all registered TrustChain tools as MCP tools.
    Responses include cryptographic signatures.
    """

    def __init__(self, tc: "TrustChain", name: str = "trustchain"):
        """Initialize MCP server.

        Args:
            tc: TrustChain instance with registered tools
            name: Server name shown to clients
        """
        _check_mcp()
        self.tc = tc
        self.name = name
        self.server = Server(name)
        self._setup_handlers()

    def _setup_handlers(self):
        """Setup MCP server handlers."""

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """Return list of available tools."""
            tools = []
            for tool_id, tool_info in self.tc._tools.items():
                # Get schema
                schema = self.tc.get_tool_schema(tool_id)
                func_def = schema["function"]

                tools.append(
                    Tool(
                        name=tool_id,
                        description=func_def.get("description", ""),
                        inputSchema=func_def.get(
                            "parameters", {"type": "object", "properties": {}}
                        ),
                    )
                )
            return tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> List[TextContent]:
            """Execute a tool and return signed response."""
            if name not in self.tc._tools:
                return [
                    TextContent(
                        type="text", text=json.dumps({"error": f"Unknown tool: {name}"})
                    )
                ]

            try:
                # Get the wrapped function
                wrapped_func = self.tc._tools[name]["func"]

                # Execute
                if asyncio.iscoroutinefunction(wrapped_func):
                    signed_response = await wrapped_func(**arguments)
                else:
                    signed_response = wrapped_func(**arguments)

                # Return result with signature metadata
                result = {
                    "result": signed_response.data,
                    "_trustchain": {
                        "signature": signed_response.signature,
                        "signature_id": signed_response.signature_id,
                        "nonce": signed_response.nonce,
                        "tool_id": signed_response.tool_id,
                        "verified": True,
                    },
                }

                return [TextContent(type="text", text=json.dumps(result, default=str))]

            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    async def run_stdio(self):
        """Run server in stdio mode (for Claude Desktop)."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, write_stream, self.server.create_initialization_options()
            )

    def serve(self):
        """Start the MCP server (blocking)."""
        asyncio.run(self.run_stdio())


def serve_mcp(tc: "TrustChain", name: str = "trustchain"):
    """Start MCP server for TrustChain tools.

    This is a blocking call that runs the server in stdio mode.

    Args:
        tc: TrustChain instance with registered tools
        name: Server name
    """
    server = TrustChainMCPServer(tc, name)
    server.serve()


def create_mcp_server(
    tc: "TrustChain", name: str = "trustchain"
) -> "TrustChainMCPServer":
    """Create MCP server instance (for advanced usage).

    Args:
        tc: TrustChain instance
        name: Server name

    Returns:
        TrustChainMCPServer instance
    """
    return TrustChainMCPServer(tc, name)


# CLI entry point
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TrustChain MCP Server")
    parser.add_argument(
        "--config", help="Path to Python config file with TrustChain setup"
    )
    args = parser.parse_args()

    if args.config:
        # Load config file
        import importlib.util

        spec = importlib.util.spec_from_file_location("config", args.config)
        config_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config_module)

        if hasattr(config_module, "tc"):
            serve_mcp(config_module.tc)
        else:
            print("Error: Config file must define 'tc' (TrustChain instance)")
            sys.exit(1)
    else:
        # Demo mode
        print("TrustChain MCP Server")
        print("Usage: python -m trustchain.integrations.mcp --config path/to/config.py")
        print("\nExample config.py:")
        print("  from trustchain import TrustChain")
        print("  tc = TrustChain()")
        print("  @tc.tool('hello')")
        print("  def hello(name: str): return f'Hello, {name}!'")


# Type hints
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trustchain.v2 import TrustChain
