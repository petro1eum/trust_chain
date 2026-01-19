#!/usr/bin/env python3
"""Example: MCP Server for Claude Desktop.

This example shows how to create a TrustChain-powered MCP server
that can be used with Claude Desktop or any other MCP client.

Setup for Claude Desktop:
1. Add to ~/Library/Application Support/Claude/claude_desktop_config.json:
   {
     "mcpServers": {
       "trustchain-example": {
         "command": "python",
         "args": ["/path/to/this/mcp_claude_desktop.py"]
       }
     }
   }
2. Restart Claude Desktop
3. Your tools will appear with cryptographic signatures!

Usage:
    python examples/mcp_claude_desktop.py
"""

from trustchain import TrustChain
from trustchain.integrations.mcp import serve_mcp

# Initialize TrustChain
tc = TrustChain()


# Define your tools with @tc.tool decorator
@tc.tool("weather")
def get_weather(city: str, units: str = "celsius") -> dict:
    """Get current weather for a city.

    Args:
        city: City name (e.g., "Moscow", "New York")
        units: Temperature units - "celsius" or "fahrenheit"
    """
    # In production, call a real weather API
    # This is just a demo
    temps = {"Moscow": 22, "New York": 25, "London": 18, "Tokyo": 28}
    temp = temps.get(city, 20)

    if units == "fahrenheit":
        temp = temp * 9 / 5 + 32

    return {
        "city": city,
        "temperature": temp,
        "units": units,
        "conditions": "sunny",
        "humidity": 65,
    }


@tc.tool("calculator")
def calculate(expression: str) -> dict:
    """Safely evaluate a mathematical expression.

    Args:
        expression: Math expression like "2 + 2" or "sqrt(16)"
    """
    import math

    # Safe evaluation with limited namespace
    allowed_names = {
        "sqrt": math.sqrt,
        "sin": math.sin,
        "cos": math.cos,
        "tan": math.tan,
        "pi": math.pi,
        "e": math.e,
        "abs": abs,
        "round": round,
        "min": min,
        "max": max,
    }

    try:
        result = eval(expression, {"__builtins__": {}}, allowed_names)
        return {"expression": expression, "result": result}
    except Exception as e:
        return {"expression": expression, "error": str(e)}


@tc.tool("database_query")
def query_users(filter_by: str = "all", limit: int = 10) -> dict:
    """Query user database with filters.

    Args:
        filter_by: Filter type - "all", "active", "premium"
        limit: Maximum number of results
    """
    # Demo data - in production, query real database
    users = [
        {"id": 1, "name": "Alice", "status": "active", "plan": "premium"},
        {"id": 2, "name": "Bob", "status": "active", "plan": "free"},
        {"id": 3, "name": "Charlie", "status": "inactive", "plan": "premium"},
        {"id": 4, "name": "Diana", "status": "active", "plan": "free"},
        {"id": 5, "name": "Eve", "status": "active", "plan": "premium"},
    ]

    if filter_by == "active":
        users = [u for u in users if u["status"] == "active"]
    elif filter_by == "premium":
        users = [u for u in users if u["plan"] == "premium"]

    return {
        "filter": filter_by,
        "count": len(users[:limit]),
        "users": users[:limit],
    }


if __name__ == "__main__":
    print("🔐 TrustChain MCP Server")
    print(f"   Tools: {list(tc._tools.keys())}")
    print("   Starting MCP server (stdio mode)...")
    print()
    print("   Add to Claude Desktop config:")
    print('   {"command": "python", "args": ["/path/to/mcp_claude_desktop.py"]}')
    print()

    # Start MCP server - this blocks and handles requests
    serve_mcp(tc, name="trustchain-example")
