"""
Example TrustChain server for JavaScript SDK demonstration.

This example shows how to:
1. Set up a TrustChain server with web API
2. Register tools for JavaScript clients
3. Run the server for testing with JavaScript SDK

To run:
1. Install dependencies: pip install 'trustchain[web]'
2. Run server: python javascript_integration.py
3. Open browser to http://localhost:8000
4. Test with JavaScript SDK
"""

import asyncio
import json
from typing import Any, Dict

from trustchain.v2 import TrustChain, TrustChainConfig
from trustchain.web_api import start_server


def main():
    """Main function to set up and run TrustChain server for JavaScript integration."""

    print("🔗 TrustChain JavaScript Integration Demo")
    print("=" * 50)

    # Create TrustChain instance with optimized config for web
    config = TrustChainConfig(
        enable_nonce=True,  # Enable nonce for security
        enable_cache=True,  # Enable caching for performance
        max_cached_responses=1000,  # Cache up to 1000 responses
    )
    tc = TrustChain(config)

    # Register demo tools for JavaScript testing
    print("🔧 Registering tools for JavaScript SDK...")

    @tc.tool("weather_api")
    def get_weather(city: str, units: str = "celsius") -> Dict[str, Any]:
        """Get weather information for a city."""
        # Simulate weather API with realistic data
        temperatures = {
            "london": 15,
            "paris": 18,
            "tokyo": 25,
            "new_york": 20,
            "berlin": 12,
            "moscow": 5,
            "sydney": 28,
            "mumbai": 32,
        }

        base_temp = temperatures.get(city.lower(), 22)
        if units == "fahrenheit":
            temperature = (base_temp * 9 / 5) + 32
        else:
            temperature = base_temp

        return {
            "city": city,
            "temperature": temperature,
            "units": units,
            "condition": "Partly cloudy",
            "humidity": 65,
            "wind_speed": 10,
            "wind_direction": "NW",
            "pressure": 1013.25,
            "visibility": 10,
        }

    @tc.tool("calculator")
    def calculate(operation: str, a: float, b: float) -> Dict[str, Any]:
        """Perform mathematical calculations."""
        operations = {
            "add": lambda x, y: x + y,
            "subtract": lambda x, y: x - y,
            "multiply": lambda x, y: x * y,
            "divide": lambda x, y: x / y if y != 0 else None,
            "power": lambda x, y: x**y,
            "modulo": lambda x, y: x % y if y != 0 else None,
        }

        if operation not in operations:
            raise ValueError(
                f"Unknown operation: {operation}. Available: {list(operations.keys())}"
            )

        result = operations[operation](a, b)
        if result is None:
            raise ValueError(f"Invalid operation: {operation}({a}, {b})")

        return {
            "operation": operation,
            "operand_a": a,
            "operand_b": b,
            "result": result,
            "calculation": f"{a} {operation} {b} = {result}",
        }

    @tc.tool("text_processor")
    async def process_text(text: str, operation: str = "upper") -> Dict[str, Any]:
        """Process text with various operations (async demo)."""
        operations = {
            "upper": lambda t: t.upper(),
            "lower": lambda t: t.lower(),
            "reverse": lambda t: t[::-1],
            "length": lambda t: len(t),
            "words": lambda t: len(t.split()),
            "capitalize": lambda t: t.capitalize(),
            "title": lambda t: t.title(),
        }

        if operation not in operations:
            raise ValueError(
                f"Unknown text operation: {operation}. Available: {list(operations.keys())}"
            )

        # Simulate async processing
        await asyncio.sleep(0.1)

        result = operations[operation](text)

        return {
            "original_text": text,
            "operation": operation,
            "result": result,
            "character_count": len(text),
            "word_count": len(text.split()),
            "processed_at": "async",
        }

    @tc.tool("currency_converter")
    def convert_currency(
        amount: float, from_currency: str, to_currency: str
    ) -> Dict[str, Any]:
        """Convert between currencies (demo with fake rates)."""
        # Fake exchange rates for demo
        rates = {
            "USD": 1.0,
            "EUR": 0.85,
            "GBP": 0.75,
            "JPY": 110.0,
            "CAD": 1.25,
            "AUD": 1.35,
            "CHF": 0.92,
            "CNY": 6.45,
        }

        from_currency = from_currency.upper()
        to_currency = to_currency.upper()

        if from_currency not in rates or to_currency not in rates:
            available = ", ".join(rates.keys())
            raise ValueError(f"Unsupported currency. Available: {available}")

        # Convert to USD first, then to target currency
        usd_amount = amount / rates[from_currency]
        converted_amount = usd_amount * rates[to_currency]

        return {
            "original_amount": amount,
            "from_currency": from_currency,
            "to_currency": to_currency,
            "converted_amount": round(converted_amount, 2),
            "exchange_rate": round(rates[to_currency] / rates[from_currency], 4),
            "conversion": f"{amount} {from_currency} = {round(converted_amount, 2)} {to_currency}",
        }

    @tc.tool("data_generator")
    def generate_data(data_type: str, count: int = 10) -> Dict[str, Any]:
        """Generate sample data for testing."""
        import random
        import string

        if count > 100:
            raise ValueError("Maximum count is 100")

        generators = {
            "numbers": lambda: [random.randint(1, 100) for _ in range(count)],
            "floats": lambda: [round(random.uniform(0, 100), 2) for _ in range(count)],
            "strings": lambda: [
                "".join(random.choices(string.ascii_letters, k=8)) for _ in range(count)
            ],
            "emails": lambda: [f"user{i}@example.com" for i in range(count)],
            "usernames": lambda: [
                f"user_{random.randint(1000, 9999)}" for _ in range(count)
            ],
        }

        if data_type not in generators:
            available = ", ".join(generators.keys())
            raise ValueError(f"Unknown data type: {data_type}. Available: {available}")

        data = generators[data_type]()

        return {
            "data_type": data_type,
            "count": count,
            "data": data,
            "sample": data[:3] if len(data) > 3 else data,
        }

    # Print registered tools
    tools = tc._tools if hasattr(tc, "_tools") else {}
    for tool_name, tool_func in tools.items():
        doc = tool_func.__doc__ or f"Tool: {tool_name}"
        is_async = asyncio.iscoroutinefunction(tool_func)
        print(
            f"   ✅ {tool_name} {'(async)' if is_async else '(sync)'}: {doc.split('.')[0]}"
        )

    print(f"\n📊 Total tools registered: {len(tools)}")

    # Print usage information
    print("\n🌐 Starting TrustChain Web API Server...")
    print("📍 Server will be available at:")
    print("   🏠 Base URL: http://localhost:8000")
    print("   ❤️  Health check: http://localhost:8000/health")
    print("   📋 API docs: http://localhost:8000/docs")
    print("   🔧 Tools list: http://localhost:8000/api/tools")
    print("   📈 Statistics: http://localhost:8000/api/stats")
    print("   🔌 WebSocket: ws://localhost:8000/ws")

    print("\n🧪 JavaScript SDK Testing:")
    print("   1. Install SDK: npm install trustchain-js")
    print("   2. Use in Node.js or browser")
    print("   3. Call tools via HTTP API")
    print("   4. Verify cryptographic signatures")

    print("\n📝 Example JavaScript usage:")
    print(
        """
    const { TrustChainClient } = require('trustchain-js');
    const client = new TrustChainClient('http://localhost:8000');
    
    // Call weather tool
    const weather = await client.callTool('weather_api', { 
        city: 'London',
        units: 'celsius'
    });
    console.log('Weather:', weather.data);
    console.log('Verified:', weather.is_verified);
    
    // Call calculator
    const calc = await client.callTool('calculator', {
        operation: 'add',
        a: 10,
        b: 5
    });
    console.log('Result:', calc.data.result);
    """
    )

    print("\n🚀 Starting server... (Press Ctrl+C to stop)")

    try:
        # Start the web server
        start_server(
            trustchain=tc,
            host="0.0.0.0",  # Allow external connections
            port=8000,
            reload=False,  # Disable for production
            workers=1,  # Single worker for demo
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        raise


if __name__ == "__main__":
    main()
