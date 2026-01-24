"""Tests for LangSmith/LangChain callback integration."""

import uuid
from unittest.mock import MagicMock

import pytest

try:
    from langchain_core.callbacks import BaseCallbackHandler

    HAS_LANGCHAIN = True
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler

        HAS_LANGCHAIN = True
    except ImportError:
        HAS_LANGCHAIN = False

pytestmark = pytest.mark.skipif(not HAS_LANGCHAIN, reason="LangChain not installed")

from trustchain.integrations.langsmith import TrustChainCallbackHandler


class TestTrustChainCallbackHandler:
    """Test callback handler functionality."""

    def test_create_handler(self):
        """Test handler creation."""
        handler = TrustChainCallbackHandler()

        assert handler is not None
        assert handler.chain_id is not None

    def test_empty_chain(self):
        """Test empty chain on creation."""
        handler = TrustChainCallbackHandler()

        assert handler.get_signed_chain() == []

    def test_chain_id_unique(self):
        """Test each handler has unique chain ID."""
        h1 = TrustChainCallbackHandler()
        h2 = TrustChainCallbackHandler()

        assert h1.chain_id != h2.chain_id

    def test_clear_chain(self):
        """Test clearing the chain."""
        handler = TrustChainCallbackHandler()

        # Add something to chain manually
        handler._sign("test", {"data": "value"})
        assert len(handler.get_signed_chain()) == 1

        old_chain_id = handler.chain_id
        handler.clear_chain()

        assert handler.get_signed_chain() == []
        assert handler.chain_id != old_chain_id


class TestToolCallbacks:
    """Test tool-related callbacks."""

    def test_on_tool_start(self):
        """Test on_tool_start callback."""
        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        handler.on_tool_start(
            serialized={"name": "weather_tool"},
            input_str="What's the weather in NYC?",
            run_id=run_id,
        )

        chain = handler.get_signed_chain()
        assert len(chain) == 1
        assert chain[0].tool_id == "weather_tool:input"

    def test_on_tool_end(self):
        """Test on_tool_end callback."""
        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        # Start tool first
        handler.on_tool_start(
            serialized={"name": "calculator"},
            input_str="2 + 2",
            run_id=run_id,
        )

        # End tool
        handler.on_tool_end(
            output="4",
            run_id=run_id,
        )

        chain = handler.get_signed_chain()
        assert len(chain) == 2
        assert chain[1].tool_id == "calculator:output"

    def test_on_tool_error(self):
        """Test on_tool_error callback."""
        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        handler.on_tool_start(
            serialized={"name": "failing_tool"},
            input_str="fail",
            run_id=run_id,
        )

        handler.on_tool_error(
            error=ValueError("Something went wrong"),
            run_id=run_id,
        )

        chain = handler.get_signed_chain()
        assert len(chain) == 2
        assert chain[1].tool_id == "failing_tool:error"
        assert "ValueError" in str(chain[1].data)

    def test_tool_duration_tracked(self):
        """Test tool duration is tracked in output."""
        import time

        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        handler.on_tool_start(
            serialized={"name": "slow_tool"},
            input_str="input",
            run_id=run_id,
        )

        time.sleep(0.01)  # Small delay

        handler.on_tool_end(output="result", run_id=run_id)

        chain = handler.get_signed_chain()
        output_data = chain[1].data
        assert "data" in output_data
        assert "duration_ms" in output_data["data"]
        assert output_data["data"]["duration_ms"] >= 10


class TestChainCallbacks:
    """Test chain-related callbacks."""

    def test_on_chain_start(self):
        """Test on_chain_start callback."""
        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        handler.on_chain_start(
            serialized={"name": "my_chain"},
            inputs={"query": "test"},
            run_id=run_id,
        )

        chain = handler.get_signed_chain()
        assert len(chain) == 1
        assert "chain:" in chain[0].tool_id

    def test_on_chain_end(self):
        """Test on_chain_end callback."""
        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        handler.on_chain_end(
            outputs={"result": "done"},
            run_id=run_id,
        )

        chain = handler.get_signed_chain()
        assert len(chain) == 1
        assert chain[0].tool_id == "chain:end"

    def test_on_chain_error(self):
        """Test on_chain_error callback."""
        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        handler.on_chain_error(
            error=RuntimeError("Chain failed"),
            run_id=run_id,
        )

        chain = handler.get_signed_chain()
        assert len(chain) == 1
        assert chain[0].tool_id == "chain:error"


class TestLLMCallbacks:
    """Test LLM-related callbacks."""

    def test_on_llm_start(self):
        """Test on_llm_start callback."""
        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        handler.on_llm_start(
            serialized={"name": "gpt-4"},
            prompts=["Hello", "World"],
            run_id=run_id,
        )

        chain = handler.get_signed_chain()
        assert len(chain) == 1
        assert chain[0].tool_id == "llm:start"

    def test_on_llm_end(self):
        """Test on_llm_end callback."""
        from langchain_core.outputs import Generation, LLMResult

        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        result = LLMResult(generations=[[Generation(text="Hello!")]])

        handler.on_llm_end(
            response=result,
            run_id=run_id,
        )

        chain = handler.get_signed_chain()
        assert len(chain) == 1
        assert chain[0].tool_id == "llm:end"


class TestChainLinking:
    """Test chain linking functionality."""

    def test_responses_are_linked(self):
        """Test responses have parent signatures."""
        handler = TrustChainCallbackHandler()

        handler._sign("step1", {"data": 1})
        handler._sign("step2", {"data": 2})
        handler._sign("step3", {"data": 3})

        chain = handler.get_signed_chain()

        # First has no parent
        assert chain[0].parent_signature is None

        # Others have parent links
        assert chain[1].parent_signature == chain[0].signature
        assert chain[2].parent_signature == chain[1].signature

    def test_has_linked_chain(self):
        """Test chain linking detection."""
        handler = TrustChainCallbackHandler()

        handler._sign("a", {})
        handler._sign("b", {})

        assert handler._has_linked_chain() is True

    def test_chain_stats(self):
        """Test chain statistics."""
        handler = TrustChainCallbackHandler()

        handler._sign("tool_a", {})
        handler._sign("tool_a", {})
        handler._sign("tool_b", {})

        stats = handler.get_chain_stats()

        assert stats["count"] == 3
        assert stats["tools"]["tool_a"] == 2
        assert stats["tools"]["tool_b"] == 1
        assert stats["has_linked_chain"] is True


class TestConfiguration:
    """Test handler configuration."""

    def test_sign_inputs_disabled(self):
        """Test disabling input signing."""
        handler = TrustChainCallbackHandler(sign_inputs=False)
        run_id = uuid.uuid4()

        handler.on_tool_start(
            serialized={"name": "tool"},
            input_str="input",
            run_id=run_id,
        )

        # Should not sign input
        assert len(handler.get_signed_chain()) == 0

    def test_sign_outputs_disabled(self):
        """Test disabling output signing."""
        handler = TrustChainCallbackHandler(sign_outputs=False)
        run_id = uuid.uuid4()

        handler.on_tool_start(
            serialized={"name": "tool"},
            input_str="input",
            run_id=run_id,
        )
        handler.on_tool_end(output="output", run_id=run_id)

        # Should only have input, not output
        chain = handler.get_signed_chain()
        assert len(chain) == 1
        assert "input" in chain[0].tool_id

    def test_custom_metadata(self):
        """Test custom metadata in signatures."""
        handler = TrustChainCallbackHandler(
            metadata={"user": "alice", "session": "123"}
        )

        handler._sign("test", {"value": 1})

        chain = handler.get_signed_chain()
        assert chain[0].data["user"] == "alice"
        assert chain[0].data["session"] == "123"
