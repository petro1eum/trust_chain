"""Tests for LLM integrations.

These tests use mocks to verify integration patterns work correctly
without requiring actual API keys.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from trustchain import TrustChain

# =============================================================================
# Test: VerifiedToolExecutor
# =============================================================================


class TestVerifiedToolExecutor:
    """Tests for the core tool executor."""

    def test_register_and_execute_tool(self):
        """Test registering and executing a tool."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()

        # Register a simple tool
        def add(a: int, b: int) -> int:
            return a + b

        executor.register_tool("add", add)

        # Execute
        result = executor.execute("add", {"a": 2, "b": 3})

        assert result.tool_id == "add"
        assert result.result == 5
        assert result.signature is not None
        assert len(result.signature) > 0

    def test_chain_of_trust(self):
        """Test that subsequent calls are chained."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("echo", lambda msg: msg)

        # First call - no parent
        r1 = executor.execute("echo", {"msg": "first"})
        assert r1.signed_response.parent_signature is None

        # Second call - should have parent
        r2 = executor.execute("echo", {"msg": "second"})
        assert r2.signed_response.parent_signature == r1.signature

        # Third call - should chain to second
        r3 = executor.execute("echo", {"msg": "third"})
        assert r3.signed_response.parent_signature == r2.signature

    def test_verify_chain(self):
        """Test chain verification."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("greet", lambda name: f"Hello, {name}!")

        executor.execute("greet", {"name": "Alice"})
        executor.execute("greet", {"name": "Bob"})
        executor.execute("greet", {"name": "Charlie"})

        assert executor.verify_chain() is True
        assert len(executor.chain) == 3

    def test_unknown_tool_raises(self):
        """Test that unknown tools raise an error."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()

        with pytest.raises(ValueError, match="Unknown tool"):
            executor.execute("nonexistent", {})

    def test_export_audit_trail(self):
        """Test audit trail export."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("action", lambda x: x)

        executor.execute("action", {"x": 1})
        executor.execute("action", {"x": 2})

        trail = executor.export_audit_trail()

        assert len(trail) == 2
        assert trail[0]["tool_id"] == "action"
        assert trail[0]["parent"] is None
        assert trail[1]["parent"] == trail[0]["signature"]

    def test_metadata_included(self):
        """Test that metadata is included in signed response."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("test", lambda: "ok")

        result = executor.execute("test", {}, metadata={"model": "gpt-4"})

        # Metadata is stored in data dict
        assert result.signed_response.data.get("metadata", {}).get("model") == "gpt-4"


# =============================================================================
# Test: OpenAI Integration Pattern
# =============================================================================


class TestOpenAIIntegration:
    """Tests for OpenAI function calling integration pattern."""

    def test_tool_call_processing(self):
        """Test processing OpenAI-style tool calls."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("get_weather", lambda location: f"Sunny in {location}")

        # Simulate OpenAI tool call response
        mock_tool_call = MagicMock()
        mock_tool_call.function.name = "get_weather"
        mock_tool_call.function.arguments = json.dumps({"location": "Tokyo"})
        mock_tool_call.id = "call_abc123"

        # Process as we would with real API
        result = executor.execute(
            tool_name=mock_tool_call.function.name,
            args=json.loads(mock_tool_call.function.arguments),
            metadata={"openai_tool_call_id": mock_tool_call.id},
        )

        assert result.result == "Sunny in Tokyo"
        assert executor.tc.verify(result.signed_response)
        assert (
            result.signed_response.data["metadata"]["openai_tool_call_id"]
            == "call_abc123"
        )

    def test_multiple_tool_calls(self):
        """Test handling multiple tool calls in one response."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("weather", lambda loc: f"Weather: {loc}")
        executor.register_tool("time", lambda tz: f"Time: {tz}")

        # Simulate multiple tool calls
        tool_calls = [
            {"name": "weather", "args": {"loc": "NYC"}},
            {"name": "time", "args": {"tz": "EST"}},
        ]

        results = []
        for tc in tool_calls:
            result = executor.execute(tc["name"], tc["args"])
            results.append(result)

        assert len(results) == 2
        assert results[1].signed_response.parent_signature == results[0].signature


# =============================================================================
# Test: OpenRouter Integration Pattern
# =============================================================================


class TestOpenRouterIntegration:
    """Tests for OpenRouter integration pattern."""

    def test_model_metadata_included(self):
        """Test that model info is included in metadata."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("calc", lambda expr: eval(expr))

        result = executor.execute(
            "calc",
            {"expr": "2+2"},
            metadata={
                "model": "anthropic/claude-3-sonnet",
                "provider": "openrouter",
            },
        )

        assert (
            result.signed_response.data["metadata"]["model"]
            == "anthropic/claude-3-sonnet"
        )
        assert result.signed_response.data["metadata"]["provider"] == "openrouter"

    def test_different_models_same_verification(self):
        """Test that verification works regardless of model."""
        from examples.llm_integrations import VerifiedToolExecutor

        # Different "models" should still produce valid signatures
        for model in ["openai/gpt-4", "anthropic/claude-3", "meta-llama/llama-3-70b"]:
            executor = VerifiedToolExecutor()
            executor.register_tool("test", lambda: "ok")

            result = executor.execute("test", {}, metadata={"model": model})

            assert executor.tc.verify(result.signed_response)


# =============================================================================
# Test: LangChain Integration Pattern
# =============================================================================


class TestLangChainIntegration:
    """Tests for LangChain tool decorator pattern."""

    def test_tool_wrapper_pattern(self):
        """Test the verified tool wrapper pattern."""
        tc = TrustChain()
        chain = []

        def make_verified_tool(tool_id: str, func):
            """Create a verified version of a function."""

            def wrapper(**kwargs):
                result = func(**kwargs)
                parent = chain[-1].signature if chain else None
                signed = tc._signer.sign(
                    tool_id=tool_id,
                    data={"result": result},
                    parent_signature=parent,
                )
                chain.append(signed)
                return {"result": result, "signature": signed.signature}

            return wrapper

        # Create verified tools
        search = make_verified_tool("search", lambda query: f"Results: {query}")
        fetch = make_verified_tool("fetch", lambda url: f"Content of {url}")

        # Use them
        r1 = search(query="test")
        r2 = fetch(url="https://example.com")

        assert "signature" in r1
        assert "signature" in r2
        assert len(chain) == 2
        assert chain[1].parent_signature == chain[0].signature


# =============================================================================
# Test: Anthropic Integration Pattern
# =============================================================================


class TestAnthropicIntegration:
    """Tests for Anthropic Claude integration pattern."""

    def test_tool_use_block_processing(self):
        """Test processing Claude tool_use blocks."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("get_stock", lambda symbol: f"${symbol}: 150.00")

        # Simulate Claude tool_use block
        mock_block = MagicMock()
        mock_block.type = "tool_use"
        mock_block.name = "get_stock"
        mock_block.input = {"symbol": "AAPL"}
        mock_block.id = "toolu_xyz"

        result = executor.execute(
            tool_name=mock_block.name,
            args=mock_block.input,
            metadata={"block_id": mock_block.id},
        )

        assert result.result == "$AAPL: 150.00"
        assert result.signed_response.data["metadata"]["block_id"] == "toolu_xyz"


# =============================================================================
# Test: End-to-End Workflow
# =============================================================================


class TestEndToEndWorkflow:
    """Test complete agent workflows."""

    def test_multi_step_agent_workflow(self):
        """Test a multi-step agent workflow with verification."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()

        # Register tools that an agent might use
        executor.register_tool("search", lambda q: f"Found: {q}")
        executor.register_tool("read_file", lambda p: f"Content of {p}")
        executor.register_tool("write_file", lambda p, c: f"Wrote to {p}")
        executor.register_tool("summarize", lambda t: f"Summary: {t[:20]}...")

        # Simulate agent workflow
        executor.execute("search", {"q": "important data"})
        r2 = executor.execute("read_file", {"p": "/data/results.txt"})
        r3 = executor.execute("summarize", {"t": r2.result})
        executor.execute("write_file", {"p": "/output/summary.txt", "c": r3.result})

        # Verify complete chain
        assert len(executor.chain) == 4
        assert executor.verify_chain()

        # Verify chain linkage
        assert executor.chain[0].parent_signature is None
        assert executor.chain[1].parent_signature == executor.chain[0].signature
        assert executor.chain[2].parent_signature == executor.chain[1].signature
        assert executor.chain[3].parent_signature == executor.chain[2].signature

    def test_audit_trail_completeness(self):
        """Test that audit trail captures all required info."""
        from examples.llm_integrations import VerifiedToolExecutor

        executor = VerifiedToolExecutor()
        executor.register_tool("action", lambda x: x * 2)

        for i in range(5):
            executor.execute("action", {"x": i})

        trail = executor.export_audit_trail()

        assert len(trail) == 5

        # Each entry should have required fields
        for entry in trail:
            assert "tool_id" in entry
            assert "timestamp" in entry
            assert "signature" in entry
            assert "parent" in entry

        # First should have no parent, rest should be chained
        assert trail[0]["parent"] is None
        for i in range(1, 5):
            assert trail[i]["parent"] == trail[i - 1]["signature"]


# =============================================================================
# Test: Demo Function
# =============================================================================


def test_demo_runs_without_error():
    """Test that the demo function runs without errors."""
    from examples.llm_integrations import demo_without_api

    # Should run without raising
    demo_without_api()
