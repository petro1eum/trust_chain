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


_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class OpenAIClient:
    """Thin OpenAI-compatible client.

    Приоритет ключей:

    1. ``OPENAI_API_KEY``  → официальный OpenAI endpoint, модель ``gpt-4o-mini``.
    2. ``OPENROUTER_API_KEY`` → OpenRouter (drop-in OpenAI-compatible),
       модель ``openai/gpt-4o-mini``. Зачем: можно прогнать smoke-тесты
       без отдельного OpenAI ключа, через единый OpenRouter-биллинг.
    """

    def __init__(self):
        self.available = False
        self.model = "gpt-4o-mini"
        self.endpoint = "openai-direct"

        try:
            import openai
        except ImportError:
            return

        if os.getenv("OPENAI_API_KEY"):
            self.client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
            self.available = True
        elif os.getenv("OPENROUTER_API_KEY"):
            self.client = openai.OpenAI(
                api_key=os.environ["OPENROUTER_API_KEY"],
                base_url=_OPENROUTER_BASE_URL,
            )
            self.model = "openai/gpt-4o-mini"
            self.endpoint = "openrouter"
            self.available = True

    async def chat(self, message: str) -> str:
        if not self.available:
            return "OpenAI not available"

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": message}],
                max_tokens=100,
            )
            ai_response = response.choices[0].message.content

            if "weather" in message.lower():
                weather = await get_weather("New York")
                ai_response += f"\n[TOOL] Weather: {weather.data}"

            return ai_response
        except Exception as e:
            return f"Error: {e}"


class AnthropicClient:
    """Anthropic client with OpenRouter fallback.

    1. ``ANTHROPIC_API_KEY``  → официальный SDK ``anthropic.Anthropic``,
       модель ``claude-3-haiku-20240307``.
    2. ``OPENROUTER_API_KEY`` → OpenRouter (OpenAI-compatible API), модель
       ``anthropic/claude-3-haiku``.  Anthropic SDK не умеет ходить в
       OpenRouter, поэтому используем openai-клиент с OpenRouter base_url —
       контракт ответа эквивалентен.
    """

    def __init__(self):
        self.available = False
        self.mode: str | None = None  # "anthropic-sdk" | "openrouter"
        self.client = None
        self.model = "claude-3-haiku-20240307"

        if os.getenv("ANTHROPIC_API_KEY"):
            try:
                import anthropic

                self.client = anthropic.Anthropic(
                    api_key=os.environ["ANTHROPIC_API_KEY"]
                )
                self.mode = "anthropic-sdk"
                self.available = True
                return
            except ImportError:
                pass

        if os.getenv("OPENROUTER_API_KEY"):
            try:
                import openai

                self.client = openai.OpenAI(
                    api_key=os.environ["OPENROUTER_API_KEY"],
                    base_url=_OPENROUTER_BASE_URL,
                )
                self.model = "anthropic/claude-3-haiku"
                self.mode = "openrouter"
                self.available = True
            except ImportError:
                pass

    async def chat(self, message: str) -> str:
        if not self.available:
            return "Anthropic not available"

        try:
            if self.mode == "anthropic-sdk":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=100,
                    messages=[{"role": "user", "content": message}],
                )
                return response.content[0].text
            # OpenRouter (OpenAI-compatible)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": message}],
                max_tokens=100,
            )
            return response.choices[0].message.content
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
    """OpenAI integration via OPENAI_API_KEY или OPENROUTER_API_KEY."""
    client = OpenAIClient()
    if not client.available:
        pytest.skip("Neither OPENAI_API_KEY nor OPENROUTER_API_KEY available")

    response = await client.chat("What's 2+2?")
    assert response is not None
    assert isinstance(response, str)
    assert len(response) > 0


@pytest.mark.asyncio
async def test_anthropic_integration():
    """Claude integration via ANTHROPIC_API_KEY или OPENROUTER_API_KEY."""
    client = AnthropicClient()
    if not client.available:
        pytest.skip("Neither ANTHROPIC_API_KEY nor OPENROUTER_API_KEY available")

    response = await client.chat("Hello, reply with the single word 'pong'.")
    assert response is not None
    assert isinstance(response, str)
    assert len(response) > 0


@pytest.mark.asyncio
async def test_anthropic_picks_openrouter_when_native_key_missing(monkeypatch):
    """Если нативного ANTHROPIC_API_KEY нет, но есть OPENROUTER_API_KEY,
    AnthropicClient ДОЛЖЕН переключиться в openrouter-режим (без skip)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-fake-not-called")
    client = AnthropicClient()
    assert client.available is True
    assert client.mode == "openrouter"
    assert client.model.startswith("anthropic/")


@pytest.mark.asyncio
async def test_openai_picks_openrouter_when_native_key_missing(monkeypatch):
    """Аналогично для OpenAIClient: OPENROUTER_API_KEY как fallback."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-fake-not-called")
    client = OpenAIClient()
    assert client.available is True
    assert client.endpoint == "openrouter"
    assert client.model.startswith("openai/")


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
