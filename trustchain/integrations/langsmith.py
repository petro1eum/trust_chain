"""LangSmith integration for TrustChain.

Auto-sign all tool calls in LangChain agents for observability.

Example:
    from trustchain.integrations.langsmith import TrustChainCallbackHandler
    from langchain.chat_models import ChatOpenAI

    handler = TrustChainCallbackHandler()
    llm = ChatOpenAI(callbacks=[handler])

    result = agent.run("What's the weather?")

    # Get signed chain
    chain = handler.get_signed_chain()
"""

from __future__ import annotations

import time
import uuid
from typing import Any

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult

    HAS_LANGCHAIN = True
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler
        from langchain.schema import LLMResult

        HAS_LANGCHAIN = True
    except ImportError:
        HAS_LANGCHAIN = False
        BaseCallbackHandler = object  # type: ignore

from trustchain.v2.signer import SignedResponse, Signer


class TrustChainCallbackHandler(BaseCallbackHandler if HAS_LANGCHAIN else object):  # type: ignore
    """LangChain callback handler that signs all tool calls.

    Automatically signs:
    - Tool inputs (on_tool_start)
    - Tool outputs (on_tool_end)
    - Chain results (on_chain_end)

    Example:
        from trustchain.integrations.langsmith import TrustChainCallbackHandler

        handler = TrustChainCallbackHandler()
        agent = create_agent(callbacks=[handler])

        result = agent.invoke("What's the weather?")

        # Get the signed chain
        for response in handler.get_signed_chain():
            print(f"{response.tool_id}: {response.signature[:16]}...")
    """

    def __init__(
        self,
        signer: Signer | None = None,
        sign_inputs: bool = True,
        sign_outputs: bool = True,
        metadata: dict[str, Any] | None = None,
    ):
        """Initialize the callback handler.

        Args:
            signer: Custom signer (will create new if not provided)
            sign_inputs: Whether to sign tool inputs
            sign_outputs: Whether to sign tool outputs
            metadata: Additional metadata to include in all signatures
        """
        if not HAS_LANGCHAIN:
            raise ImportError(
                "LangChain required for TrustChainCallbackHandler. "
                "Install with: pip install langchain-core>=0.1.0"
            )

        self._signer = signer or Signer()
        self._sign_inputs = sign_inputs
        self._sign_outputs = sign_outputs
        self._metadata = metadata or {}
        self._chain: list[SignedResponse] = []
        self._chain_id = str(uuid.uuid4())
        self._pending_tools: dict[str, dict[str, Any]] = {}

    @property
    def chain_id(self) -> str:
        """Get unique ID for this chain/session."""
        return self._chain_id

    def get_signed_chain(self) -> list[SignedResponse]:
        """Get all signed responses from this session.

        Returns:
            List of SignedResponse objects in order
        """
        return list(self._chain)

    def clear_chain(self) -> None:
        """Clear the signed chain and start fresh."""
        self._chain = []
        self._chain_id = str(uuid.uuid4())

    def get_chain_stats(self) -> dict[str, Any]:
        """Get statistics about the current chain.

        Returns:
            dict with chain_id, count, tools, etc.
        """
        tools = {}
        for response in self._chain:
            tool_id = response.tool_id
            if tool_id not in tools:
                tools[tool_id] = 0
            tools[tool_id] += 1

        return {
            "chain_id": self._chain_id,
            "count": len(self._chain),
            "tools": tools,
            "has_linked_chain": self._has_linked_chain(),
        }

    def _has_linked_chain(self) -> bool:
        """Check if chain has proper parent links."""
        if len(self._chain) <= 1:
            return True

        for i in range(1, len(self._chain)):
            if self._chain[i].parent_signature != self._chain[i - 1].signature:
                return False
        return True

    def _sign(
        self,
        tool_id: str,
        data: Any,
        event_type: str = "output",
    ) -> SignedResponse:
        """Sign data and add to chain."""
        parent_sig = self._chain[-1].signature if self._chain else None

        full_data = {
            "data": data,
            "event_type": event_type,
            "chain_id": self._chain_id,
            **self._metadata,
        }

        response = self._signer.sign(
            tool_id=tool_id,
            data=full_data,
            parent_signature=parent_sig,
        )

        self._chain.append(response)
        return response

    # LangChain Callback Methods

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts running."""
        tool_name = serialized.get("name", "unknown_tool")

        # Store pending tool info
        self._pending_tools[str(run_id)] = {
            "name": tool_name,
            "input": input_str,
            "start_time": time.time(),
            "tags": tags,
            "metadata": metadata,
        }

        if self._sign_inputs:
            self._sign(
                tool_id=f"{tool_name}:input",
                data={
                    "input": input_str,
                    "run_id": str(run_id),
                    "tags": tags,
                },
                event_type="tool_input",
            )

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes successfully."""
        pending = self._pending_tools.pop(str(run_id), {})
        tool_name = pending.get("name", "unknown_tool")

        if self._sign_outputs:
            duration = time.time() - pending.get("start_time", time.time())

            self._sign(
                tool_id=f"{tool_name}:output",
                data={
                    "output": str(output)[:1000],  # Truncate large outputs
                    "run_id": str(run_id),
                    "duration_ms": int(duration * 1000),
                },
                event_type="tool_output",
            )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors."""
        pending = self._pending_tools.pop(str(run_id), {})
        tool_name = pending.get("name", "unknown_tool")

        self._sign(
            tool_id=f"{tool_name}:error",
            data={
                "error": str(error),
                "error_type": type(error).__name__,
                "run_id": str(run_id),
            },
            event_type="tool_error",
        )

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when chain starts."""
        chain_name = serialized.get("name", serialized.get("id", ["chain"])[-1])

        if self._sign_inputs:
            # Only sign input keys, not full values (may be large)
            self._sign(
                tool_id=f"chain:{chain_name}:start",
                data={
                    "input_keys": list(inputs.keys()),
                    "run_id": str(run_id),
                    "tags": tags,
                },
                event_type="chain_start",
            )

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when chain finishes."""
        if self._sign_outputs:
            self._sign(
                tool_id="chain:end",
                data={
                    "output_keys": list(outputs.keys()),
                    "run_id": str(run_id),
                },
                event_type="chain_end",
            )

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when chain errors."""
        self._sign(
            tool_id="chain:error",
            data={
                "error": str(error),
                "error_type": type(error).__name__,
                "run_id": str(run_id),
            },
            event_type="chain_error",
        )

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts."""
        if self._sign_inputs:
            self._sign(
                tool_id="llm:start",
                data={
                    "model": serialized.get("name", "unknown"),
                    "prompt_count": len(prompts),
                    "run_id": str(run_id),
                },
                event_type="llm_start",
            )

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM finishes."""
        if self._sign_outputs:
            self._sign(
                tool_id="llm:end",
                data={
                    "generations_count": len(response.generations),
                    "run_id": str(run_id),
                },
                event_type="llm_end",
            )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM errors."""
        self._sign(
            tool_id="llm:error",
            data={
                "error": str(error),
                "error_type": type(error).__name__,
                "run_id": str(run_id),
            },
            event_type="llm_error",
        )
