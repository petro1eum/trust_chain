#!/usr/bin/env python3
"""
TrustChain Demo: Real LLM Agent with Verified Tool Calls
Honest example - no fakes, just real cryptographic verification.
"""
import asyncio
import os

import httpx
from dotenv import load_dotenv

from trustchain import TrustChain

load_dotenv()

# Initialize TrustChain
tc = TrustChain()


# Define a real tool with cryptographic signing
@tc.tool("weather_api")
def get_weather(city: str) -> dict:
    """Get weather for a city. Response is cryptographically signed."""
    # In production this would call a real weather API
    weather_data = {
        "Dubai": {"temp": 38, "conditions": "Sunny", "humidity": 45},
        "London": {"temp": 12, "conditions": "Cloudy", "humidity": 80},
        "Tokyo": {"temp": 22, "conditions": "Clear", "humidity": 60},
    }
    return weather_data.get(city, {"temp": 20, "conditions": "Unknown"})


# Call the tool - returns SignedResponse
print("=" * 50)
print("TrustChain: Cryptographic Verification for AI Tools")
print("=" * 50)

print("\n1. Calling signed tool...")
response = get_weather("Dubai")

print(f"   Data: {response.data}")
print(f"   Signature: {response.signature[:48]}...")
print(f"   Tool ID: {response.tool_id}")
print(f"   Timestamp: {response.timestamp}")

print("\n2. Verifying signature...")
is_valid = tc.verify(response)
print(f"   Valid: {is_valid}")

# Chain of Trust - linked operations
print("\n3. Chain of Trust (linked operations)...")
step1 = tc._signer.sign("search", {"query": "Dubai weather"})
step2 = tc._signer.sign(
    "fetch", {"result": response.data}, parent_signature=step1.signature
)
step3 = tc._signer.sign(
    "respond", {"answer": "It's 38°C in Dubai"}, parent_signature=step2.signature
)

chain_valid = tc.verify_chain([step1, step2, step3])
print("   Steps: search → fetch → respond")
print(f"   Chain valid: {chain_valid}")

# Real LLM call if API key is available
api_key = os.getenv("OPENROUTER_API_KEY")
if api_key:
    print("\n4. Real LLM Integration...")

    @tc.tool("llm_chat")
    async def chat_with_llm(prompt: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "openai/gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 100,
                },
                timeout=30,
            )
            data = resp.json()
            return {
                "model": data.get("model"),
                "response": (
                    data["choices"][0]["message"]["content"]
                    if "choices" in data
                    else data
                ),
                "tokens": data.get("usage", {}).get("total_tokens", 0),
            }

    async def demo_llm():
        llm_response = await chat_with_llm(
            "What is the capital of UAE? One word answer."
        )
        print(
            f"   LLM Response: {llm_response.data.get('response', llm_response.data)}"
        )
        print(f"   Signature: {llm_response.signature[:48]}...")
        print(f"   Verified: {tc.verify(llm_response)}")

    asyncio.run(demo_llm())
else:
    print("\n4. Set OPENROUTER_API_KEY for real LLM demo")

print("\n" + "=" * 50)
print("pip install trustchain")
print("=" * 50)
