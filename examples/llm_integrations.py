"""LLM Integration Examples for TrustChain.

This module demonstrates how to integrate TrustChain with popular LLM providers
and frameworks to create verifiable, auditable AI tool calls.

Supported integrations:
- OpenAI (GPT-4, GPT-3.5)
- OpenRouter (unified API for multiple models)
- LangChain (tool decorators)
- Anthropic Claude (direct API)

Usage:
    pip install trustchain[ai]  # Includes openai, langchain-core

    # Set your API key
    export OPENAI_API_KEY=sk-...
    # or
    export OPENROUTER_API_KEY=sk-or-...
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable

from trustchain import TrustChain
from trustchain.v2.signer import SignedResponse

# =============================================================================
# Core: Verified Tool Wrapper
# =============================================================================


@dataclass
class VerifiedToolResult:
    """Result of a verified tool execution."""

    tool_id: str
    result: Any
    signed_response: SignedResponse
    signature: str

    def to_dict(self) -> dict:
        """Export as dictionary."""
        return {
            "tool_id": self.tool_id,
            "result": self.result,
            "signature": self.signature,
            "verified": True,
        }


class VerifiedToolExecutor:
    """Wraps tool execution with TrustChain signatures.

    This is the core integration class that can be used with any LLM provider.
    """

    def __init__(self, trust_chain: TrustChain | None = None):
        self.tc = trust_chain or TrustChain()
        self.chain: list[SignedResponse] = []
        self.tools: dict[str, Callable] = {}

    def register_tool(self, name: str, func: Callable) -> None:
        """Register a tool function."""
        self.tools[name] = func

    def execute(
        self, tool_name: str, args: dict, metadata: dict | None = None
    ) -> VerifiedToolResult:
        """Execute a tool and sign the result."""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")

        # Execute the tool
        result = self.tools[tool_name](**args)

        # Get parent signature for chain of trust
        parent_sig = self.chain[-1].signature if self.chain else None

        # Sign the response using internal signer
        signed = self.tc._signer.sign(
            tool_id=tool_name,
            data={"result": result, "metadata": {"args": args, **(metadata or {})}},
            parent_signature=parent_sig,
        )

        self.chain.append(signed)

        return VerifiedToolResult(
            tool_id=tool_name,
            result=result,
            signed_response=signed,
            signature=signed.signature,
        )

    def verify_chain(self) -> bool:
        """Verify the entire execution chain."""
        for response in self.chain:
            if not self.tc.verify(response):
                return False
        return True

    def export_audit_trail(self) -> list[dict]:
        """Export the audit trail for compliance."""
        return [
            {
                "tool_id": r.tool_id,
                "timestamp": r.timestamp,
                "signature": r.signature,
                "parent": r.parent_signature,
            }
            for r in self.chain
        ]


# =============================================================================
# OpenAI Integration
# =============================================================================


def openai_function_calling_example():
    """Example: OpenAI function calling with TrustChain verification.

    This pattern intercepts tool call responses and signs them before
    returning to the conversation.
    """
    try:
        from openai import OpenAI
    except ImportError:
        print("Install openai: pip install openai")
        return

    # Initialize
    client = OpenAI()
    executor = VerifiedToolExecutor()

    # Define tools
    def get_weather(location: str) -> str:
        """Get weather for a location."""
        # Simulated response
        return f"The weather in {location} is sunny, 22°C"

    def search_database(query: str) -> str:
        """Search the database."""
        return f"Found 3 results for: {query}"

    executor.register_tool("get_weather", get_weather)
    executor.register_tool("search_database", search_database)

    # OpenAI tools schema
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get the current weather in a location",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {"type": "string", "description": "City name"}
                    },
                    "required": ["location"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_database",
                "description": "Search the database",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"}
                    },
                    "required": ["query"],
                },
            },
        },
    ]

    # Chat completion with tools
    messages = [{"role": "user", "content": "What's the weather in Tokyo?"}]

    response = client.chat.completions.create(
        model="gpt-4-turbo-preview",
        messages=messages,
        tools=tools,
        tool_choice="auto",
    )

    # Process tool calls
    if response.choices[0].message.tool_calls:
        for tool_call in response.choices[0].message.tool_calls:
            # Execute and sign
            result = executor.execute(
                tool_name=tool_call.function.name,
                args=json.loads(tool_call.function.arguments),
                metadata={"openai_tool_call_id": tool_call.id},
            )

            print(f"Tool: {result.tool_id}")
            print(f"Result: {result.result}")
            print(f"Signature: {result.signature[:32]}...")
            print(f"Verified: {executor.tc.verify(result.signed_response)}")

    # Export audit trail
    print("\nAudit Trail:")
    for entry in executor.export_audit_trail():
        print(f"  {entry['tool_id']}: {entry['signature'][:16]}...")


# =============================================================================
# OpenRouter Integration
# =============================================================================


def openrouter_example():
    """Example: OpenRouter integration (supports Claude, GPT-4, Llama, etc.).

    OpenRouter provides a unified API for multiple LLM providers.
    TrustChain works the same way - sign tool outputs regardless of the model.
    """
    try:
        from openai import OpenAI
    except ImportError:
        print("Install openai: pip install openai")
        return

    # OpenRouter uses OpenAI-compatible API
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.getenv("OPENROUTER_API_KEY"),
    )

    executor = VerifiedToolExecutor()

    # Register tools
    def calculate(expression: str) -> str:
        """Safely evaluate a math expression."""
        try:
            # Only allow safe math operations
            allowed = set("0123456789+-*/.(). ")
            if all(c in allowed for c in expression):
                return str(eval(expression))
            return "Invalid expression"
        except Exception as e:
            return f"Error: {e}"

    executor.register_tool("calculate", calculate)

    # Make request to any model through OpenRouter
    response = client.chat.completions.create(
        model="anthropic/claude-3-sonnet",  # or "openai/gpt-4", "meta-llama/llama-3-70b"
        messages=[{"role": "user", "content": "Calculate 15 * 7 + 23"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "calculate",
                    "description": "Calculate a math expression",
                    "parameters": {
                        "type": "object",
                        "properties": {"expression": {"type": "string"}},
                        "required": ["expression"],
                    },
                },
            }
        ],
    )

    # Process and verify
    if response.choices[0].message.tool_calls:
        for tc in response.choices[0].message.tool_calls:
            result = executor.execute(
                tool_name=tc.function.name,
                args=json.loads(tc.function.arguments),
                metadata={
                    "model": response.model,
                    "provider": "openrouter",
                },
            )
            print(f"Model: {response.model}")
            print(f"Result: {result.result}")
            print(f"Signature: {result.signature[:32]}...")


# =============================================================================
# LangChain Integration
# =============================================================================


def langchain_tool_decorator_example():
    """Example: LangChain tool with TrustChain verification.

    Decorate LangChain tools to automatically sign their outputs.
    """
    try:
        from langchain_core.tools import tool
    except ImportError:
        print("Install langchain-core: pip install langchain-core")
        return

    tc = TrustChain()
    chain: list[SignedResponse] = []

    def verified_tool(tool_id: str):
        """Decorator that adds TrustChain verification to a LangChain tool."""

        def decorator(func):
            @tool
            def wrapper(*args, **kwargs):
                # Execute original function
                result = func(*args, **kwargs)

                # Sign the result
                parent = chain[-1].signature if chain else None
                signed = tc.sign_response(
                    tool_id=tool_id,
                    output=result,
                    parent_signature=parent,
                    metadata={"args": kwargs},
                )
                chain.append(signed)

                # Return result with signature attached
                return {
                    "result": result,
                    "signature": signed.signature,
                    "verified": True,
                }

            wrapper.__doc__ = func.__doc__
            return wrapper

        return decorator

    # Define verified tools
    @verified_tool("web_search")
    def web_search(query: str) -> str:
        """Search the web for information."""
        return f"Results for: {query}"

    @verified_tool("file_reader")
    def file_reader(path: str) -> str:
        """Read a file from the filesystem."""
        return f"Contents of {path}"

    # Use the tools
    result1 = web_search.invoke({"query": "TrustChain Python library"})
    print(f"Search result: {result1}")

    result2 = file_reader.invoke({"path": "/etc/hosts"})
    print(f"File result: {result2}")

    # Verify chain
    print(f"\nChain length: {len(chain)}")
    for r in chain:
        print(f"  {r.tool_id}: verified={tc.verify(r)}")


# =============================================================================
# Anthropic Claude Integration
# =============================================================================


def anthropic_example():
    """Example: Anthropic Claude with TrustChain verification.

    Claude's tool use follows a similar pattern to OpenAI.
    """
    try:
        import anthropic
    except ImportError:
        print("Install anthropic: pip install anthropic")
        return

    client = anthropic.Anthropic()
    executor = VerifiedToolExecutor()

    # Register tools
    def get_stock_price(symbol: str) -> str:
        """Get stock price."""
        # Simulated
        prices = {"AAPL": 178.50, "GOOGL": 141.25, "MSFT": 378.90}
        price = prices.get(symbol.upper(), 0)
        return f"${price:.2f}"

    executor.register_tool("get_stock_price", get_stock_price)

    # Claude tool use
    response = client.messages.create(
        model="claude-3-sonnet-20240229",
        max_tokens=1024,
        tools=[
            {
                "name": "get_stock_price",
                "description": "Get the current stock price",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "symbol": {"type": "string", "description": "Stock ticker"}
                    },
                    "required": ["symbol"],
                },
            }
        ],
        messages=[{"role": "user", "content": "What's Apple's stock price?"}],
    )

    # Process tool use blocks
    for block in response.content:
        if block.type == "tool_use":
            result = executor.execute(
                tool_name=block.name,
                args=block.input,
                metadata={"block_id": block.id},
            )
            print(f"Tool: {block.name}")
            print(f"Result: {result.result}")
            print(f"Signature: {result.signature[:32]}...")


# =============================================================================
# Main Demo
# =============================================================================


def demo_without_api():
    """Demo that works without API keys."""
    print("=" * 60)
    print("TrustChain LLM Integration Demo (No API Required)")
    print("=" * 60)

    # Create executor
    executor = VerifiedToolExecutor()

    # Register mock tools
    def mock_llm_query(prompt: str) -> str:
        return f"LLM Response to: {prompt[:50]}..."

    def mock_database(query: str) -> str:
        return f"[DB] 5 records matching '{query}'"

    def mock_calculation(expr: str) -> str:
        try:
            return str(eval(expr))
        except Exception:
            return "Error"

    executor.register_tool("llm_query", mock_llm_query)
    executor.register_tool("database", mock_database)
    executor.register_tool("calculate", mock_calculation)

    # Simulate an agent workflow
    print("\n1. Agent receives user request...")
    print("   User: 'Calculate 2+2, then search the database for the result'")

    print("\n2. Agent executes tools with verification:")

    # Step 1: Calculate
    r1 = executor.execute("calculate", {"expr": "2+2"})
    print(f"   calculate('2+2') = {r1.result}")
    print(f"   Signature: {r1.signature[:32]}...")

    # Step 2: Database query (chained)
    r2 = executor.execute("database", {"query": f"value={r1.result}"})
    print(f"   database('value={r1.result}') = {r2.result}")
    print(f"   Signature: {r2.signature[:32]}...")
    print(f"   Parent: {r2.signed_response.parent_signature[:32]}...")

    # Step 3: LLM summary
    r3 = executor.execute(
        "llm_query", {"prompt": f"Summarize: {r1.result}, {r2.result}"}
    )
    print(f"   llm_query(...) = {r3.result}")
    print(f"   Signature: {r3.signature[:32]}...")

    # Verify complete chain
    print("\n3. Verify execution chain:")
    is_valid = executor.verify_chain()
    print(f"   Chain valid: {is_valid}")
    print(f"   Chain length: {len(executor.chain)}")

    # Export audit trail
    print("\n4. Audit trail for compliance:")
    for i, entry in enumerate(executor.export_audit_trail(), 1):
        print(f"   {i}. {entry['tool_id']}")
        print(f"      sig: {entry['signature'][:24]}...")
        if entry["parent"]:
            print(f"      parent: {entry['parent'][:24]}...")

    print("\n" + "=" * 60)
    print("All tool calls are cryptographically signed and chained!")
    print("=" * 60)


if __name__ == "__main__":
    demo_without_api()
