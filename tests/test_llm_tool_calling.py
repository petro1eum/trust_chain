#!/usr/bin/env python3
"""
🤖 TrustChain LLM Tool Calling Test (v2 API)

Tests LLM tool calling with cryptographically signed responses.
Uses the modern v2 TrustChain API.

Run with: python tests/test_llm_tool_calling.py
"""

import asyncio
import time
from typing import Any, Dict, List

import pytest

from trustchain import TrustChain, TrustChainConfig

# Create TrustChain instance
tc = TrustChain(TrustChainConfig(enable_nonce=False))


# ==================== TRUSTED TOOLS (v2 API) ====================


@tc.tool("weather_api")
async def weather_tool(location: str) -> Dict[str, Any]:
    """Get weather data - signed for authenticity."""
    await asyncio.sleep(0.05)
    return {
        "location": location,
        "temp": 22,
        "condition": "sunny",
        "humidity": 65,
        "timestamp": time.time(),
        "source": "WeatherAPI",
    }


@tc.tool("payment_system")
async def payment_processor(
    amount: float, currency: str, recipient: str
) -> Dict[str, Any]:
    """Process payment - for financial operations."""
    await asyncio.sleep(0.1)
    return {
        "transaction_id": f"tx_{int(time.time())}",
        "amount": amount,
        "currency": currency,
        "recipient": recipient,
        "status": "completed",
        "fee": amount * 0.025,
        "timestamp": time.time(),
    }


@tc.tool("calculator")
async def calculator_tool(expression: str) -> Dict[str, Any]:
    """Calculate expression - signed for audit trail."""
    await asyncio.sleep(0.02)
    try:
        result = eval(expression.replace(" ", ""))
    except Exception:
        result = "Error"
    return {"expression": expression, "result": result, "timestamp": time.time()}


@tc.tool("data_analytics")
async def analytics_tool(data: List[float]) -> Dict[str, Any]:
    """Analyze data - signed for data integrity."""
    await asyncio.sleep(0.08)
    if not data:
        return {"error": "No data"}
    return {
        "count": len(data),
        "mean": sum(data) / len(data),
        "min": min(data),
        "max": max(data),
        "sum": sum(data),
        "timestamp": time.time(),
    }


# ==================== AI AGENT ====================


class AIAgent:
    """Simulates an AI Agent that can call tools."""

    def __init__(self, name: str, model: str = "gpt-4o"):
        self.name = name
        self.model = model
        self.tool_calls_made = []

    async def chat(self, message: str) -> str:
        """Chat and call tools based on message content."""
        if "weather" in message.lower():
            result = await weather_tool("New York")
            self.tool_calls_made.append(
                {
                    "tool": "weather_tool",
                    "result": result.data,
                    "signature": result.signature[:20] + "...",
                    "verified": result.is_verified,
                }
            )
            return f"Weather: {result.data['temp']}°C, {result.data['condition']}"

        elif any(kw in message.lower() for kw in ["payment", "send", "transfer"]):
            result = await payment_processor(100.0, "USD", "friend@example.com")
            self.tool_calls_made.append(
                {
                    "tool": "payment_processor",
                    "result": result.data,
                    "signature": result.signature[:20] + "...",
                    "verified": result.is_verified,
                }
            )
            return f"Payment: ${result.data['amount']} sent"

        elif "calculate" in message.lower():
            result = await calculator_tool("15 * 8 + 7")
            self.tool_calls_made.append(
                {
                    "tool": "calculator_tool",
                    "result": result.data,
                    "signature": result.signature[:20] + "...",
                    "verified": result.is_verified,
                }
            )
            return f"Result: {result.data['result']}"

        elif "analyze" in message.lower():
            result = await analytics_tool([1, 2, 3, 4, 5])
            self.tool_calls_made.append(
                {
                    "tool": "analytics_tool",
                    "result": result.data,
                    "signature": result.signature[:20] + "...",
                    "verified": result.is_verified,
                }
            )
            return f"Mean: {result.data['mean']}"

        return f"Regular response to: {message}"


# ==================== PYTEST TESTS ====================


@pytest.fixture
def agent():
    """Create fresh agent for each test."""
    return AIAgent("TestAgent")


@pytest.mark.asyncio
async def test_conversational_ai_without_tools(agent):
    """Test regular AI conversation - no tools needed."""
    response = await agent.chat("Hello, how are you?")
    assert "Regular response" in response
    assert len(agent.tool_calls_made) == 0


@pytest.mark.asyncio
async def test_weather_tool_calling(agent):
    """Test AI calling weather tool - signature required."""
    await agent.chat("What's the weather?")
    assert len(agent.tool_calls_made) == 1
    assert agent.tool_calls_made[0]["tool"] == "weather_tool"
    assert agent.tool_calls_made[0]["verified"] is True
    assert "signature" in agent.tool_calls_made[0]


@pytest.mark.asyncio
async def test_payment_tool_calling(agent):
    """Test AI calling payment tool."""
    await agent.chat("Send $100 to my friend")
    assert len(agent.tool_calls_made) == 1
    assert agent.tool_calls_made[0]["tool"] == "payment_processor"
    assert agent.tool_calls_made[0]["verified"] is True
    assert agent.tool_calls_made[0]["result"]["status"] == "completed"


@pytest.mark.asyncio
async def test_calculator_tool_calling(agent):
    """Test AI calling calculator tool."""
    await agent.chat("Please calculate something")
    assert len(agent.tool_calls_made) == 1
    assert agent.tool_calls_made[0]["tool"] == "calculator_tool"
    assert agent.tool_calls_made[0]["result"]["result"] == 127  # 15*8+7


@pytest.mark.asyncio
async def test_analytics_tool_calling(agent):
    """Test AI calling analytics tool."""
    await agent.chat("Analyze data please")
    assert len(agent.tool_calls_made) == 1
    assert agent.tool_calls_made[0]["tool"] == "analytics_tool"
    assert agent.tool_calls_made[0]["result"]["mean"] == 3.0


@pytest.mark.asyncio
async def test_multi_tool_conversation(agent):
    """Test AI using multiple tools in one conversation."""
    await agent.chat("What's the weather?")
    await agent.chat("Calculate something")
    await agent.chat("Send payment")
    await agent.chat("Hello!")  # No tool

    assert len(agent.tool_calls_made) == 3
    tools_used = [c["tool"] for c in agent.tool_calls_made]
    assert "weather_tool" in tools_used
    assert "calculator_tool" in tools_used
    assert "payment_processor" in tools_used


@pytest.mark.asyncio
async def test_all_tool_calls_signed(agent):
    """Verify all tool calls are signed."""
    await agent.chat("What's the weather?")
    await agent.chat("Calculate something")
    await agent.chat("Analyze data")

    for call in agent.tool_calls_made:
        assert call["verified"] is True
        assert call["signature"] is not None


@pytest.mark.asyncio
async def test_concurrent_agents():
    """Test multiple AI agents calling tools concurrently."""
    agents = [AIAgent(f"Agent{i}") for i in range(3)]

    tasks = [
        agents[0].chat("What's the weather?"),
        agents[1].chat("Calculate something"),
        agents[2].chat("Analyze data"),
    ]

    await asyncio.gather(*tasks)

    for agent in agents:
        assert len(agent.tool_calls_made) == 1
        assert agent.tool_calls_made[0]["verified"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
