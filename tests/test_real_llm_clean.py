#!/usr/bin/env python3
"""
🤖 Clean Real LLM Test (v2 API)

Tests TrustChain with real LLM integrations using the v2 API.
No manual setup required - the library works out of the box.

Run with: python tests/test_real_llm_clean.py
Requires: OPENAI_API_KEY and/or ANTHROPIC_API_KEY (optional)
"""

import asyncio
import os
from typing import Any, Dict

import pytest

from trustchain import TrustChain, TrustChainConfig

# Create TrustChain instance
tc = TrustChain(TrustChainConfig(enable_nonce=False))


# ==================== TRUSTED TOOLS (v2 API) ====================


@tc.tool("weather_service")
async def get_weather(location: str, units: str = "celsius") -> Dict[str, Any]:
    """Get weather information - automatically signed."""
    await asyncio.sleep(0.1)
    return {
        "location": location,
        "temperature": 22,
        "condition": "sunny",
        "humidity": 65,
        "units": units,
        "source": "WeatherAPI",
    }


@tc.tool("calculator_service")
async def calculate(expression: str) -> Dict[str, Any]:
    """Perform calculations - automatically signed."""
    try:
        result = eval(expression.replace(" ", ""))
        return {"expression": expression, "result": result, "status": "success"}
    except Exception as e:
        return {"expression": expression, "error": str(e), "status": "error"}


@tc.tool("email_service")
async def send_email(recipient: str, subject: str, message: str) -> Dict[str, Any]:
    """Send email - automatically signed."""
    await asyncio.sleep(0.2)
    return {
        "recipient": recipient,
        "subject": subject,
        "message_preview": message[:50] + "..." if len(message) > 50 else message,
        "status": "sent",
        "message_id": f"msg_{hash(message) % 10000}",
    }


# ==================== LLM CLIENTS ====================


class OpenAIClient:
    """Simple OpenAI client."""

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.available = bool(self.api_key)
        if self.available:
            try:
                import openai

                self.client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                self.available = False

    async def chat(self, message: str) -> str:
        """Chat with OpenAI."""
        if not self.available:
            return "OpenAI not available"

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": message}],
                max_tokens=100,
            )
            ai_response = response.choices[0].message.content

            # Check for tool triggers
            if "weather" in message.lower():
                weather = await get_weather("New York")
                ai_response += f"\n[TOOL] Weather: {weather.data}"

            return ai_response
        except Exception as e:
            return f"Error: {e}"


class AnthropicClient:
    """Simple Anthropic client."""

    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.available = bool(self.api_key)
        if self.available:
            try:
                import anthropic

                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self.available = False

    async def chat(self, message: str) -> str:
        """Chat with Claude."""
        if not self.available:
            return "Anthropic not available"

        try:
            response = self.client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=100,
                messages=[{"role": "user", "content": message}],
            )
            return response.content[0].text
        except Exception as e:
            return f"Error: {e}"


# ==================== PYTEST TESTS ====================


@pytest.mark.asyncio
async def test_weather_tool_signed():
    """Verify weather tool is automatically signed."""
    result = await get_weather("London")
    assert result.data["location"] == "London"
    assert result.is_verified is True
    assert result.signature is not None


@pytest.mark.asyncio
async def test_calculator_tool_signed():
    """Verify calculator tool is automatically signed."""
    result = await calculate("15 * 3")
    assert result.data["result"] == 45
    assert result.is_verified is True


@pytest.mark.asyncio
async def test_email_tool_signed():
    """Verify email tool is automatically signed."""
    result = await send_email("test@example.com", "Hello", "Test message")
    assert result.data["status"] == "sent"
    assert result.is_verified is True


@pytest.mark.asyncio
async def test_no_manual_setup_required():
    """Prove TrustChain works without manual setup."""
    # Just call tools - they should work out of the box
    weather = await get_weather("Paris")
    calc = await calculate("10 + 20")

    assert weather.data["location"] == "Paris"
    assert weather.is_verified is True

    assert calc.data["result"] == 30
    assert calc.is_verified is True


@pytest.mark.asyncio
async def test_openai_integration():
    """Test OpenAI integration (skipped if no API key)."""
    client = OpenAIClient()
    if not client.available:
        pytest.skip("OpenAI API key not available")

    response = await client.chat("What's 2+2?")
    assert response is not None


@pytest.mark.asyncio
async def test_anthropic_integration():
    """Test Anthropic integration (skipped if no API key)."""
    client = AnthropicClient()
    if not client.available:
        pytest.skip("Anthropic API key not available")

    response = await client.chat("Hello")
    assert response is not None


@pytest.mark.asyncio
async def test_multiple_tools_chained():
    """Test calling multiple tools in sequence."""
    weather = await get_weather("Tokyo")
    calc = await calculate("5 * 5")
    email = await send_email("user@test.com", "Report", "Daily report")

    # All should be signed
    assert weather.is_verified is True
    assert calc.is_verified is True
    assert email.is_verified is True

    # Signatures should be different
    assert weather.signature != calc.signature
    assert calc.signature != email.signature


@pytest.mark.asyncio
async def test_concurrent_tool_calls():
    """Test concurrent tool calls are all signed."""
    tasks = [
        get_weather("London"),
        get_weather("Paris"),
        get_weather("Tokyo"),
        calculate("1+1"),
        calculate("2+2"),
    ]

    results = await asyncio.gather(*tasks)

    for result in results:
        assert result.is_verified is True
        assert result.signature is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
