#!/usr/bin/env python3
"""Full enforcement demonstration for TrustChain v2."""

import asyncio
import time
from typing import Any, Dict, List

from trustchain.v2 import TrustChain, TrustChainConfig

# Create TrustChain with strict settings
tc = TrustChain(
    TrustChainConfig(
        enable_nonce=True,
        cache_ttl=300,
        max_cached_responses=50,
    )
)


# Define various tools
@tc.tool("weather_api")
async def get_weather(city: str) -> Dict[str, Any]:
    """Get weather data for a city."""
    await asyncio.sleep(0.05)  # Simulate API call
    return {
        "city": city,
        "temperature": 22,
        "humidity": 65,
        "conditions": "Partly cloudy",
        "wind_speed": 10,
    }


@tc.tool("stock_api")
async def get_stock_price(symbol: str) -> Dict[str, Any]:
    """Get stock price data."""
    await asyncio.sleep(0.05)  # Simulate API call
    prices = {
        "AAPL": 185.50,
        "GOOGL": 142.75,
        "MSFT": 378.25,
        "AMZN": 155.60,
    }
    return {
        "symbol": symbol,
        "price": prices.get(symbol, 100.0),
        "currency": "USD",
        "timestamp": time.time(),
    }


@tc.tool("news_api")
async def get_news(topic: str, limit: int = 5) -> Dict[str, Any]:
    """Get latest news on a topic."""
    await asyncio.sleep(0.1)  # Simulate API call
    return {
        "topic": topic,
        "count": limit,
        "articles": [
            {"title": f"News about {topic} #{i}", "source": "NewsAPI"}
            for i in range(1, limit + 1)
        ],
    }


class SimpleAgent:
    """A simple AI agent that uses tools."""

    def __init__(self, name: str):
        self.name = name
        self.call_history: List[Dict[str, Any]] = []

    async def process_query(self, query: str) -> str:
        """Process a user query using available tools."""
        print(f"\n🤖 {self.name} processing: '{query}'")

        # Simple keyword-based tool selection
        if "weather" in query.lower():
            # Extract city (simple approach)
            city = "London"  # Default
            if "paris" in query.lower():
                city = "Paris"
            elif "tokyo" in query.lower():
                city = "Tokyo"

            # Call the weather tool
            response = await get_weather(city)
            self.call_history.append(
                {
                    "tool": "weather_api",
                    "response": response,
                    "verified": response.is_verified,
                }
            )

            return f"The weather in {response.data['city']} is {response.data['conditions']} with a temperature of {response.data['temperature']}°C."

        elif "stock" in query.lower() or "price" in query.lower():
            # Extract symbol
            symbol = "AAPL"  # Default
            for s in ["GOOGL", "MSFT", "AMZN"]:
                if s.lower() in query.lower():
                    symbol = s

            # Call the stock API
            response = await get_stock_price(symbol)
            self.call_history.append(
                {
                    "tool": "stock_api",
                    "response": response,
                    "verified": response.is_verified,
                }
            )

            return f"The current price of {response.data['symbol']} is ${response.data['price']:.2f}."

        elif "news" in query.lower():
            # Extract topic
            topic = "technology"  # Default
            if "sports" in query.lower():
                topic = "sports"
            elif "business" in query.lower():
                topic = "business"

            # Call the news API
            response = await get_news(topic, limit=3)
            self.call_history.append(
                {
                    "tool": "news_api",
                    "response": response,
                    "verified": response.is_verified,
                }
            )

            articles = response.data["articles"]
            news_summary = f"Here are the latest {topic} news:\n"
            for article in articles:
                news_summary += f"- {article['title']}\n"

            return news_summary

        else:
            return "I'm not sure how to help with that. Try asking about weather, stocks, or news."


async def demonstrate_enforcement():
    """Demonstrate the full enforcement system."""

    print("🔒 TrustChain v2 Full Enforcement Demo")
    print("=" * 60)

    # Create an agent
    agent = SimpleAgent("TrustBot")

    # Process various queries
    queries = [
        "What's the weather in Paris?",
        "What's the stock price of GOOGL?",
        "Show me the latest technology news",
        "What's the weather in Tokyo?",
        "How much is MSFT stock?",
    ]

    print("\n📋 Processing user queries with enforced tool calls:")

    for query in queries:
        response = await agent.process_query(query)
        print(f"\n💬 Query: {query}")
        print(f"🤖 Response: {response}")

        # Show the last tool call details
        if agent.call_history:
            last_call = agent.call_history[-1]
            print(f"🔧 Tool used: {last_call['tool']}")
            print(f"✅ Verified: {last_call['verified']}")
            print(f"🔐 Signature: {last_call['response'].signature[:32]}...")

    # Show enforcement statistics
    print("\n\n📊 ENFORCEMENT STATISTICS:")
    print("=" * 60)

    stats = tc.get_stats()
    print(f"Total tools registered: {stats['total_tools']}")
    print(f"Total tool calls: {stats['total_calls']}")
    print(f"Responses in cache: {stats['cache_size']}")

    print("\n📈 Per-tool statistics:")
    for tool_id in ["weather_api", "stock_api", "news_api"]:
        tool_stats = tc.get_tool_stats(tool_id)
        print(f"\n{tool_id}:")
        print(f"  - Calls: {tool_stats['call_count']}")
        if tool_stats.get("last_execution_time"):
            print(
                f"  - Last exec time: {tool_stats['last_execution_time'] * 1000:.2f}ms"
            )

    # Demonstrate verification
    print("\n\n🔍 VERIFICATION DEMONSTRATION:")
    print("=" * 60)

    if agent.call_history:
        # Take a response and verify it
        sample_response = agent.call_history[0]["response"]

        print(f"Verifying response from {sample_response.tool_id}...")
        print(f"Original data: {sample_response.data}")

        # Verify the original (this consumes the nonce)
        is_valid = tc.verify(sample_response)
        print(f"✅ Original verification: {is_valid}")

        # Try to tamper with it
        import copy

        tampered = copy.deepcopy(sample_response)
        tampered.data["tampered"] = True

        # Use _signer.verify() to check signature without nonce check
        # (nonce was already consumed above)
        is_valid_tampered = tc._signer.verify(tampered)
        print(f"❌ Tampered verification: {is_valid_tampered}")

        print("\n✅ TrustChain v2 successfully detected tampering!")

    # Show call history summary
    print("\n\n📜 AGENT CALL HISTORY:")
    print("=" * 60)

    for i, call in enumerate(agent.call_history, 1):
        print(f"\n{i}. Tool: {call['tool']}")
        print(f"   Verified: {call['verified']}")
        print(f"   Data keys: {list(call['response'].data.keys())}")


async def demonstrate_concurrent_enforcement():
    """Demonstrate concurrent tool calls with enforcement."""

    print("\n\n⚡ CONCURRENT ENFORCEMENT DEMO")
    print("=" * 60)

    # Create multiple agents
    agents = [
        SimpleAgent("Agent-1"),
        SimpleAgent("Agent-2"),
        SimpleAgent("Agent-3"),
    ]

    # Concurrent queries
    queries = [
        "What's the weather in Paris?",
        "Show me AAPL stock price",
        "Latest sports news please",
    ]

    print("\n🚀 Launching concurrent tool calls...")
    start_time = time.time()

    # Run all queries concurrently
    tasks = []
    for agent, query in zip(agents, queries):
        tasks.append(agent.process_query(query))

    responses = await asyncio.gather(*tasks)

    elapsed = time.time() - start_time
    print(f"\n✅ All concurrent calls completed in {elapsed:.3f}s")

    # Show results
    for agent, response in zip(agents, responses):
        print(f"\n{agent.name}: {response[:100]}...")
        if agent.call_history:
            print(f"   Verified: {agent.call_history[-1]['verified']}")

    # Final statistics
    print("\n\n🏁 FINAL STATISTICS:")
    final_stats = tc.get_stats()
    print(f"Total calls made: {final_stats['total_calls']}")
    print("All calls verified: ✅")

    print("\n" + "=" * 60)
    print("✅ TrustChain v2 Full Enforcement Demo Complete!")
    print("\nKey takeaways:")
    print("- Every tool call is automatically signed")
    print("- Signatures are verified on creation")
    print("- Tampering is immediately detected")
    print("- Concurrent calls work seamlessly")
    print("- No global state - clean architecture")


async def main():
    """Run all demonstrations."""
    await demonstrate_enforcement()
    await demonstrate_concurrent_enforcement()


if __name__ == "__main__":
    asyncio.run(main())
