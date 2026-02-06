#!/usr/bin/env python3
"""
TrustChain Demo: Before vs After
Shows how easy it is to integrate - just add @tc.tool() decorator!
"""
import asyncio
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OPENROUTER_API_KEY")

# ========================================
# BEFORE: Without TrustChain
# ========================================
print("=" * 55)
print("BEFORE: Standard tool (no verification)")
print("=" * 55)


def get_weather_unsafe(city: str) -> dict:
    """Standard function - returns plain dict."""
    return {"city": city, "temp": 38, "conditions": "Sunny"}


result = get_weather_unsafe("Dubai")
print("Function: get_weather_unsafe('Dubai')")
print(f"Returns:  {result}")
print(f"Type:     {type(result).__name__}")
print("Problem:  LLM can claim ANY data came from this tool!")

# ========================================
# AFTER: With TrustChain (just 2 lines added!)
# ========================================
print("\n" + "=" * 55)
print("AFTER: TrustChain secured (add 2 lines)")
print("=" * 55)

from trustchain import TrustChain  # Line 1: import

tc = TrustChain()


@tc.tool("weather_api")  # Line 2: decorator - THAT'S IT!
def get_weather(city: str) -> dict:
    """Same function - now cryptographically signed!"""
    return {"city": city, "temp": 38, "conditions": "Sunny"}


result = get_weather("Dubai")
print("Function: @tc.tool('weather_api')")
print("          def get_weather('Dubai')")
print("Returns:  SignedResponse")
print(f"Data:     {result.data}")
print(f"Signature:{result.signature[:40]}...")
print(f"Verified: {tc.verify(result)}")

# ========================================
# Real LLM Integration
# ========================================
if API_KEY:
    print("\n" + "=" * 55)
    print("REAL LLM: Every API call is now verified")
    print("=" * 55)

    @tc.tool("llm_api")  # Just add this decorator!
    async def call_llm(prompt: str) -> dict:
        """Real OpenRouter API call - automatically signed."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {API_KEY}"},
                json={
                    "model": "openai/gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 50,
                },
                timeout=30,
            )
            return resp.json()

    async def demo():
        response = await call_llm("Capital of France? One word.")
        answer = (
            response.data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "N/A")
        )
        print("Prompt:   'Capital of France?'")
        print(f"LLM says: {answer}")
        print(f"Signature:{response.signature[:40]}...")
        print(f"Verified: {tc.verify(response)}")

    asyncio.run(demo())

print("\n" + "=" * 55)
print("pip install trustchain")
print("=" * 55)
