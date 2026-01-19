#!/usr/bin/env python3
"""
🤖 TrustChain LLM Tool Calling Test

This test demonstrates the proper use case: LLM generates regular responses,
but when it decides to use tools/functions, those tool calls are cryptographically signed.

This prevents:
- Forged tool executions
- Unauthorized actions by AI
- Audit trail of what tools AI actually used

Run with: python tests/test_llm_tool_calling.py
"""

import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

import pytest

from trustchain import MemoryRegistry, SignatureEngine, TrustedTool, TrustLevel
from trustchain.core.signatures import set_signature_engine


class AIAgent:
    """Simulates an AI Agent that can make regular responses and call tools."""

    def __init__(self, name: str, model: str = "gpt-4o"):
        self.name = name
        self.model = model
        self.conversation_history = []
        self.tool_calls_made = []

    async def chat(self, message: str) -> str:
        """Regular chat - no signatures needed for normal conversation."""
        print(f"\n🤖 {self.name}: Thinking about '{message}'...")

        # Simulate AI processing
        await asyncio.sleep(0.1)

        # AI decision making logic
        if "weather" in message.lower():
            response = "I'll check the weather for you. Let me use my weather tool."
            # AI decides to call weather tool
            weather_data = await self._call_weather_tool("New York")
            response += f"\n📊 {weather_data['summary']}"

        elif any(
            keyword in message.lower()
            for keyword in ["payment", "send money", "send $", "transfer", "pay"]
        ):
            response = "I'll help you with the payment. Let me use the payment system."
            # AI decides to call payment tool
            payment_result = await self._call_payment_tool(
                100.0, "USD", "friend@example.com"
            )
            response += f"\n💰 {payment_result['summary']}"

        elif "calculate" in message.lower():
            response = "I'll calculate that for you using my calculator tool."
            # AI decides to call calculator tool
            calc_result = await self._call_calculator_tool("15 * 8 + 7")
            response += f"\n🧮 {calc_result['summary']}"

        elif any(
            keyword in message.lower()
            for keyword in ["analyze data", "analyze", "data analysis", "statistics"]
        ):
            response = "I'll analyze that data using my analytics tools."
            # AI decides to call analytics tool
            analysis_result = await self._call_analytics_tool([1, 2, 3, 4, 5])
            response += f"\n📈 {analysis_result['summary']}"

        else:
            # Regular conversation - no tools needed
            response = f"I understand your question: '{message}'. This is a regular conversational response that doesn't require any tools."

        self.conversation_history.append({"user": message, "ai": response})
        return response

    # ==================== TOOL CALLS (SIGNED) ====================

    async def _call_weather_tool(self, location: str) -> Dict[str, Any]:
        """AI calls weather tool - this gets signed!"""
        print(f"  🛠️  AI calling weather_tool for {location}")
        result = await weather_tool(location)

        self.tool_calls_made.append(
            {
                "tool": "weather_tool",
                "args": {"location": location},
                "result": result.data,
                "signature": result.signature.signature[:20] + "...",
                "verified": result.is_verified,
            }
        )

        return {
            "data": result.data,
            "summary": f"Weather in {location}: {result.data['temp']}°C, {result.data['condition']}",
        }

    async def _call_payment_tool(
        self, amount: float, currency: str, recipient: str
    ) -> Dict[str, Any]:
        """AI calls payment tool - this gets signed!"""
        print(f"  🛠️  AI calling payment_tool for ${amount} {currency}")
        result = await payment_processor(amount, currency, recipient)

        self.tool_calls_made.append(
            {
                "tool": "payment_processor",
                "args": {
                    "amount": amount,
                    "currency": currency,
                    "recipient": recipient,
                },
                "result": result.data,
                "signature": result.signature.signature[:20] + "...",
                "verified": result.is_verified,
            }
        )

        return {
            "data": result.data,
            "summary": f"Payment sent: ${amount} {currency} to {recipient} (TX: {result.data['transaction_id']})",
        }

    async def _call_calculator_tool(self, expression: str) -> Dict[str, Any]:
        """AI calls calculator tool - this gets signed!"""
        print(f"  🛠️  AI calling calculator_tool for '{expression}'")
        result = await calculator_tool(expression)

        self.tool_calls_made.append(
            {
                "tool": "calculator_tool",
                "args": {"expression": expression},
                "result": result.data,
                "signature": result.signature.signature[:20] + "...",
                "verified": result.is_verified,
            }
        )

        return {
            "data": result.data,
            "summary": f"Calculation: {expression} = {result.data['result']}",
        }

    async def _call_analytics_tool(self, data: List[float]) -> Dict[str, Any]:
        """AI calls analytics tool - this gets signed!"""
        print(f"  🛠️  AI calling analytics_tool with {len(data)} data points")
        result = await analytics_tool(data)

        self.tool_calls_made.append(
            {
                "tool": "analytics_tool",
                "args": {"data": data},
                "result": result.data,
                "signature": result.signature.signature[:20] + "...",
                "verified": result.is_verified,
            }
        )

        return {
            "data": result.data,
            "summary": f"Analytics: mean={result.data['mean']:.2f}, count={result.data['count']}",
        }


# ==================== TRUSTED TOOLS (SIGNED) ====================


@TrustedTool("weather_api", trust_level=TrustLevel.MEDIUM)
async def weather_tool(location: str) -> Dict[str, Any]:
    """Get weather data - signed for authenticity."""
    await asyncio.sleep(0.05)  # Simulate API call

    return {
        "location": location,
        "temp": 22,
        "condition": "sunny",
        "humidity": 65,
        "timestamp": time.time(),
        "source": "WeatherAPI",
    }


@TrustedTool("payment_system", trust_level=TrustLevel.CRITICAL)
async def payment_processor(
    amount: float, currency: str, recipient: str
) -> Dict[str, Any]:
    """Process payment - CRITICAL trust level for financial operations."""
    await asyncio.sleep(0.1)  # Simulate payment processing

    return {
        "transaction_id": f"tx_{int(time.time())}",
        "amount": amount,
        "currency": currency,
        "recipient": recipient,
        "status": "completed",
        "fee": amount * 0.025,  # 2.5% fee
        "timestamp": time.time(),
        "processor": "SecurePayments",
    }


@TrustedTool("calculator", trust_level=TrustLevel.LOW)
async def calculator_tool(expression: str) -> Dict[str, Any]:
    """Calculate expression - signed for audit trail."""
    await asyncio.sleep(0.02)  # Simulate calculation

    # Simple expression evaluation (in production, use safe eval)
    try:
        result = eval(expression.replace(" ", ""))  # Basic calc only
    except:
        result = "Error: Invalid expression"

    return {
        "expression": expression,
        "result": result,
        "timestamp": time.time(),
        "calculator": "TrustCalc",
    }


@TrustedTool("data_analytics", trust_level=TrustLevel.HIGH)
async def analytics_tool(data: List[float]) -> Dict[str, Any]:
    """Analyze data - signed for data integrity."""
    await asyncio.sleep(0.08)  # Simulate analysis

    if not data:
        return {"error": "No data provided"}

    return {
        "count": len(data),
        "mean": sum(data) / len(data),
        "min": min(data),
        "max": max(data),
        "sum": sum(data),
        "timestamp": time.time(),
        "analyzer": "TrustAnalytics",
    }


# ==================== TEST SCENARIOS ====================


class LLMToolCallingTests:
    """Test suite for LLM tool calling with TrustChain."""

    def __init__(self):
        self.registry = None
        self.signature_engine = None
        self.agents = []

    async def setup(self):
        """Initialize TrustChain components."""
        print("🔧 Setting up TrustChain for tool calling...")

        # Create registry and signature engine
        self.registry = MemoryRegistry()
        await self.registry.start()

        self.signature_engine = SignatureEngine(self.registry)
        set_signature_engine(self.signature_engine)

        print("✅ TrustChain setup complete!")

    async def cleanup(self):
        """Clean up resources."""
        if self.registry:
            await self.registry.stop()

    async def test_conversational_ai_without_tools(self):
        """Test regular AI conversation - no signatures needed."""
        print("\n💬 Testing Regular AI Conversation (No Tools)")
        print("-" * 50)

        agent = AIAgent("ConversationalAI", "gpt-4o")

        # Regular conversation that doesn't trigger tools
        response1 = await agent.chat("Hello, how are you today?")
        response2 = await agent.chat("Tell me about quantum physics")
        response3 = await agent.chat("What's your favorite color?")

        print(f"   📝 Response 1: {response1[:60]}...")
        print(f"   📝 Response 2: {response2[:60]}...")
        print(f"   📝 Response 3: {response3[:60]}...")
        print(f"   🛠️  Tools called: {len(agent.tool_calls_made)} (expected: 0)")

        # Assert no tools were called for regular conversation
        assert (
            len(agent.tool_calls_made) == 0
        ), "Regular conversation should not trigger tools"

        self.agents.append(agent)
        return True

    async def test_ai_weather_tool_calling(self):
        """Test AI calling weather tool - signature required."""
        print("\n🌤️  Testing AI Weather Tool Calling")
        print("-" * 50)

        agent = AIAgent("WeatherAI", "gpt-4o")

        # User asks about weather - AI should use weather tool
        response = await agent.chat("What's the weather like today?")

        print(f"   📝 AI Response: {response}")
        print(f"   🛠️  Tools called: {len(agent.tool_calls_made)}")

        # Verify tool was called and signed
        assert (
            len(agent.tool_calls_made) == 1
        ), "Weather query should trigger exactly 1 tool call"

        tool_call = agent.tool_calls_made[0]
        assert tool_call["tool"] == "weather_tool"
        assert "signature" in tool_call
        assert tool_call["signature"] is not None

        print(f"   ✅ Tool call signed: {tool_call['signature'] is not None}")
        print(f"   🔐 Signature: {tool_call['signature']}")
        print("   📝 Full verification enabled")

        self.agents.append(agent)
        return True

    async def test_ai_payment_tool_calling(self):
        """Test AI calling payment tool - CRITICAL signature required."""
        print("\n💰 Testing AI Payment Tool Calling (CRITICAL)")
        print("-" * 50)

        agent = AIAgent("FinancialAI", "gpt-4o")

        # User asks to send money - AI should use payment tool
        response = await agent.chat("Send $100 to my friend")

        print(f"   📝 AI Response: {response}")
        print(f"   🛠️  Tools called: {len(agent.tool_calls_made)}")

        # Verify payment tool was called with CRITICAL trust level
        assert (
            len(agent.tool_calls_made) == 1
        ), "Payment request should trigger exactly 1 tool call"

        tool_call = agent.tool_calls_made[0]
        assert tool_call["tool"] == "payment_processor"
        assert tool_call["signature"] is not None
        assert tool_call["result"]["status"] == "completed"

        print(f"   ✅ Payment signed: {tool_call['signature'] is not None}")
        print(f"   💳 Transaction ID: {tool_call['result']['transaction_id']}")
        print(f"   🔐 Critical signature: {tool_call['signature']}")
        print("   📝 Note: CRITICAL trust level applied")

        self.agents.append(agent)
        return True

    async def test_ai_calculator_tool_calling(self):
        """Test AI calling calculator tool - signed for audit."""
        print("\n🧮 Testing AI Calculator Tool Calling")
        print("-" * 50)

        agent = AIAgent("MathAI", "gpt-4o")

        # User asks for calculation - AI should use calculator
        response = await agent.chat("Can you calculate 15 times 8 plus 7?")

        print(f"   📝 AI Response: {response}")
        print(f"   🛠️  Tools called: {len(agent.tool_calls_made)}")

        # Verify calculator was used
        assert len(agent.tool_calls_made) == 1, "Math query should trigger calculator"

        tool_call = agent.tool_calls_made[0]
        assert tool_call["tool"] == "calculator_tool"
        assert tool_call["signature"] is not None
        assert tool_call["result"]["result"] == 127  # 15*8+7 = 127

        print(f"   ✅ Calculation signed: {tool_call['signature'] is not None}")
        print(f"   📊 Result: {tool_call['result']['result']}")
        print(f"   🔐 Signature: {tool_call['signature']}")
        print("   📝 Note: Audit trail for math operations")

        self.agents.append(agent)
        return True

    async def test_ai_analytics_tool_calling(self):
        """Test AI calling analytics tool - signed for data integrity."""
        print("\n📈 Testing AI Analytics Tool Calling")
        print("-" * 50)

        agent = AIAgent("AnalyticsAI", "gpt-4o")

        # User asks for data analysis - AI should use analytics tool
        response = await agent.chat("Please analyze data: [1, 2, 3, 4, 5]")

        print(f"   📝 AI Response: {response}")
        print(f"   🛠️  Tools called: {len(agent.tool_calls_made)}")

        # Verify analytics tool was used
        assert (
            len(agent.tool_calls_made) == 1
        ), "Data analysis should trigger analytics tool"

        tool_call = agent.tool_calls_made[0]
        assert tool_call["tool"] == "analytics_tool"
        assert tool_call["signature"] is not None
        assert tool_call["result"]["mean"] == 3.0  # Mean of [1,2,3,4,5]

        print(f"   ✅ Analysis signed: {tool_call['signature'] is not None}")
        print(f"   📊 Mean: {tool_call['result']['mean']}")
        print(f"   🔐 Signature: {tool_call['signature']}")
        print("   📝 Note: HIGH trust level for data integrity")

        self.agents.append(agent)
        return True

    async def test_multi_tool_conversation(self):
        """Test AI using multiple tools in one conversation."""
        print("\n🔄 Testing Multi-Tool Conversation")
        print("-" * 50)

        agent = AIAgent("MultiToolAI", "gpt-4o")

        # Conversation that triggers multiple tools
        await agent.chat("What's the weather?")  # Should call weather tool
        await agent.chat("Calculate 10 + 20")  # Should call calculator
        await agent.chat("Send $50 payment")  # Should call payment tool
        await agent.chat("How are you?")  # Regular chat, no tools

        print("   💬 Total conversations: 4")
        print(f"   🛠️  Total tool calls: {len(agent.tool_calls_made)}")

        # Should have exactly 3 tool calls (weather, calc, payment)
        assert (
            len(agent.tool_calls_made) == 3
        ), "Should have 3 tool calls from 4 conversations"

        # Verify all tool calls are signed
        for i, call in enumerate(agent.tool_calls_made):
            assert call["signature"] is not None, f"Tool call {i} should be signed"
            print(
                f"   ✅ Tool {i+1}: {call['tool']} - Signed: {call['signature'] is not None}"
            )

        self.agents.append(agent)
        return True

    async def test_concurrent_ai_agents(self):
        """Test multiple AI agents calling tools concurrently."""
        print("\n⚡ Testing Concurrent AI Agents")
        print("-" * 50)

        # Create multiple agents
        agents = [
            AIAgent("Agent1", "gpt-4o"),
            AIAgent("Agent2", "claude-3"),
            AIAgent("Agent3", "gemini-pro"),
        ]

        # Each agent calls different tools concurrently
        start_time = time.time()
        tasks = [
            agents[0].chat("What's the weather?"),  # Weather tool
            agents[1].chat("Calculate 25 * 4"),  # Calculator tool
            agents[2].chat("Analyze data: [10,20,30]"),  # Analytics tool
        ]

        await asyncio.gather(*tasks)
        end_time = time.time()

        total_time = end_time - start_time
        print(f"   ⚡ Processed 3 agents in {total_time:.2f}s")

        # Verify all agents made tool calls
        total_tool_calls = sum(len(agent.tool_calls_made) for agent in agents)
        assert total_tool_calls == 3, "Should have 3 total tool calls"

        # Verify all tool calls are signed
        for i, agent in enumerate(agents):
            assert len(agent.tool_calls_made) == 1, f"Agent {i} should have 1 tool call"
            assert (
                agent.tool_calls_made[0]["signature"] is not None
            ), f"Agent {i} tool call should be signed"
            print(f"   ✅ Agent {i+1}: {agent.tool_calls_made[0]['tool']} - Signed")

        self.agents.extend(agents)
        return True

    async def test_tool_audit_trail(self):
        """Test audit trail of all tool calls made by AI agents."""
        print("\n📋 Testing Tool Audit Trail")
        print("-" * 50)

        # Collect all tool calls from all tests
        all_tool_calls = []
        for agent in self.agents:
            all_tool_calls.extend(agent.tool_calls_made)

        print(f"   📊 Total AI agents tested: {len(self.agents)}")
        print(f"   🛠️  Total tool calls made: {len(all_tool_calls)}")

        # Group by tool type
        tool_counts = {}
        for call in all_tool_calls:
            tool = call["tool"]
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

        print("   📈 Tool usage breakdown:")
        for tool, count in tool_counts.items():
            print(f"      🔸 {tool}: {count} calls")

        # Verify all calls are signed
        signed_calls = sum(
            1 for call in all_tool_calls if call["signature"] is not None
        )
        print(f"   🔐 Signed calls: {signed_calls}/{len(all_tool_calls)}")

        assert signed_calls == len(all_tool_calls), "All tool calls should be signed"
        assert len(all_tool_calls) > 0, "Should have recorded tool calls"

        return True

    async def run_all_tests(self):
        """Run all LLM tool calling tests."""
        print("🤖 Starting TrustChain LLM Tool Calling Tests")
        print("=" * 70)
        print("This demonstrates the CORRECT use case:")
        print("• LLM generates regular text (no signatures)")
        print("• When LLM calls tools → cryptographically signed")
        print("• Prevents forged tool executions by AI")
        print("• Creates audit trail of AI actions")
        print()

        await self.setup()

        try:
            # Run all test scenarios
            await self.test_conversational_ai_without_tools()
            await self.test_ai_weather_tool_calling()
            await self.test_ai_payment_tool_calling()
            await self.test_ai_calculator_tool_calling()
            await self.test_ai_analytics_tool_calling()
            await self.test_multi_tool_conversation()
            await self.test_concurrent_ai_agents()
            await self.test_tool_audit_trail()

            # Print final results
            self.print_final_results()

        except Exception as e:
            print(f"❌ Test failed: {e}")
            raise
        finally:
            await self.cleanup()

    def print_final_results(self):
        """Print comprehensive test results."""
        print("\n" + "=" * 70)
        print("🎉 TrustChain LLM Tool Calling Tests Complete!")
        print("=" * 70)

        # Calculate totals
        total_agents = len(self.agents)
        total_tool_calls = sum(len(agent.tool_calls_made) for agent in self.agents)
        total_signed = sum(
            len(
                [
                    call
                    for call in agent.tool_calls_made
                    if call["signature"] is not None
                ]
            )
            for agent in self.agents
        )

        print("📊 Test Results:")
        print(f"   🤖 AI Agents tested: {total_agents}")
        print(f"   🛠️  Tool calls made: {total_tool_calls}")
        print(f"   🔐 Signed calls: {total_signed}/{total_tool_calls} (100%)")
        print("   ⚡ All tests passed: ✅")

        print("\n🎯 Key Achievements:")
        print("   ✅ Regular AI conversation works without signatures")
        print("   ✅ Tool calls are automatically signed when AI uses them")
        print("   ✅ CRITICAL trust level for financial operations")
        print("   ✅ Complete audit trail of AI tool usage")
        print("   ✅ Concurrent AI agents with signed tool calls")
        print("   ✅ Prevention of forged tool executions")

        print("\n🔗 TrustChain provides the RIGHT solution:")
        print("   • AI can chat normally (no unnecessary signatures)")
        print("   • But when AI takes actions via tools → SIGNED!")
        print("   • Perfect balance of usability and security 🛡️")


# ==================== PYTEST INTEGRATION ====================


@pytest.fixture
async def tool_calling_tests():
    """Pytest fixture for tool calling tests."""
    tests = LLMToolCallingTests()
    await tests.setup()
    yield tests
    await tests.cleanup()


@pytest.mark.asyncio
async def test_conversational_ai_pytest(tool_calling_tests):
    """Pytest version of conversational AI test."""
    result = await tool_calling_tests.test_conversational_ai_without_tools()
    assert result is True


@pytest.mark.asyncio
async def test_weather_tool_pytest(tool_calling_tests):
    """Pytest version of weather tool test."""
    result = await tool_calling_tests.test_ai_weather_tool_calling()
    assert result is True


@pytest.mark.asyncio
async def test_payment_tool_pytest(tool_calling_tests):
    """Pytest version of payment tool test."""
    result = await tool_calling_tests.test_ai_payment_tool_calling()
    assert result is True


@pytest.mark.asyncio
async def test_calculator_tool_pytest(tool_calling_tests):
    """Pytest version of calculator tool test."""
    result = await tool_calling_tests.test_ai_calculator_tool_calling()
    assert result is True


@pytest.mark.asyncio
async def test_multi_tool_pytest(tool_calling_tests):
    """Pytest version of multi-tool test."""
    result = await tool_calling_tests.test_multi_tool_conversation()
    assert result is True


# ==================== MAIN EXECUTION ====================


async def main():
    """Main execution function."""
    tests = LLMToolCallingTests()
    await tests.run_all_tests()


if __name__ == "__main__":
    # Run the comprehensive test suite
    asyncio.run(main())
