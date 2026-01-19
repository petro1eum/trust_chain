"""TrustChain Integrations.

Available integrations:
- LangChain: to_langchain_tool, to_langchain_tools
- MCP: serve_mcp, create_mcp_server
"""

# LangChain (optional)
try:
    from .langchain import (
        to_langchain_tool,
        to_langchain_tools,
        TrustChainLangChainTool,
    )
except ImportError:
    to_langchain_tool = None
    to_langchain_tools = None
    TrustChainLangChainTool = None

# MCP (optional)
try:
    from .mcp import (
        serve_mcp,
        create_mcp_server,
        TrustChainMCPServer,
    )
except ImportError:
    serve_mcp = None
    create_mcp_server = None
    TrustChainMCPServer = None

__all__ = [
    "to_langchain_tool",
    "to_langchain_tools",
    "TrustChainLangChainTool",
    "serve_mcp",
    "create_mcp_server",
    "TrustChainMCPServer",
]
