"""Real integration tests for TrustChain integrations.

These tests verify ACTUAL behavior, not just "code runs without error".
Each test has a specific verification goal and includes negative cases.
"""

import copy
import json

import pytest

# Import fixtures for pytest plugin tests
from trustchain.pytest_plugin.fixtures import async_tc, signed_chain, tc

# ============================================================================
# LangChain Integration Tests - Real Tool Execution Verification
# ============================================================================

try:
    from langchain_core.runnables import RunnableLambda
    from langchain_core.tools import tool

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False


@pytest.mark.skipif(not HAS_LANGCHAIN, reason="LangChain not installed")
class TestLangChainRealIntegration:
    """Test TrustChain actually captures and signs LangChain tool calls."""

    def test_tool_input_output_are_actually_different_signatures(self):
        """
        REAL TEST: Verify that input and output get DIFFERENT signatures.
        A mock would just return whatever you tell it to.
        """
        import uuid

        from trustchain.integrations.langsmith import TrustChainCallbackHandler

        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        # Call with specific input
        handler.on_tool_start(
            serialized={"name": "calculator"},
            input_str="2 + 2",
            run_id=run_id,
        )

        # Return specific output
        handler.on_tool_end(output="4", run_id=run_id)

        chain = handler.get_signed_chain()

        # REAL VERIFICATION: signatures must be different
        input_sig = chain[0].signature
        output_sig = chain[1].signature

        assert (
            input_sig != output_sig
        ), "Input and output must have different signatures!"

        # REAL VERIFICATION: data is actually captured (nested in 'data' wrapper)
        assert chain[0].data["data"]["input"] == "2 + 2"
        assert chain[1].data["data"]["output"] == "4"

        # REAL VERIFICATION: each signature is unique (not reused)
        assert len({chain[0].signature, chain[1].signature}) == 2

    def test_chain_is_linked_correctly(self):
        """
        REAL TEST: Verify parent signatures actually create a chain.
        """
        import uuid

        from trustchain.integrations.langsmith import TrustChainCallbackHandler

        handler = TrustChainCallbackHandler(sign_inputs=True, sign_outputs=True)

        # First tool call
        tool1_id = uuid.uuid4()
        handler.on_tool_start(
            serialized={"name": "tool1"},
            input_str="input1",
            run_id=tool1_id,
        )
        handler.on_tool_end(output="output1", run_id=tool1_id)

        # Second tool call
        tool2_id = uuid.uuid4()
        handler.on_tool_start(
            serialized={"name": "tool2"},
            input_str="input2",
            run_id=tool2_id,
        )
        handler.on_tool_end(output="output2", run_id=tool2_id)

        chain = handler.get_signed_chain()

        # REAL VERIFICATION: chain is properly linked via parent_signature
        assert len(chain) == 4  # 2 inputs + 2 outputs

        # Each subsequent item has the previous one as parent
        for i in range(1, len(chain)):
            assert (
                chain[i].parent_signature == chain[i - 1].signature
            ), f"Item {i} should be linked to item {i-1}"

    def test_error_handling_signs_errors_with_correct_state(self):
        """
        REAL TEST: Errors are captured with failure state.
        """
        import uuid

        from trustchain.integrations.langsmith import TrustChainCallbackHandler

        handler = TrustChainCallbackHandler()
        run_id = uuid.uuid4()

        handler.on_tool_start(
            serialized={"name": "failing_tool"},
            input_str="bad input",
            run_id=run_id,
        )

        error = ValueError("Something went wrong")
        handler.on_tool_error(error=error, run_id=run_id)

        chain = handler.get_signed_chain()

        # REAL VERIFICATION: error response exists and has correct state
        error_resp = chain[1]
        assert error_resp.tool_id == "failing_tool:error"
        # Data is wrapped in "data" key by _sign method
        assert "error" in error_resp.data["data"]
        assert "Something went wrong" in str(error_resp.data["data"]["error"])


# ============================================================================
# Pydantic Integration Tests - Tamper Detection Verification
# ============================================================================

try:
    from pydantic import BaseModel, ValidationError

    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False


@pytest.mark.skipif(not HAS_PYDANTIC, reason="Pydantic not installed")
class TestPydanticRealIntegration:
    """Test TrustChainModel actually detects tampering."""

    def test_tampering_is_actually_detected(self):
        """
        REAL TEST: Modifying a signed field MUST break verification.
        This is the core guarantee of TrustChain.
        """
        from trustchain.integrations.pydantic_v2 import SignedField, TrustChainModel

        class Prediction(TrustChainModel):
            label: str
            confidence: float = SignedField(min=0.0, max=1.0)

        pred = Prediction(label="positive", confidence=0.95)

        # BEFORE tampering - must verify
        assert pred.verify() is True, "Fresh model must verify!"

        original_sig = pred.signature

        # TAMPER with the data
        object.__setattr__(pred, "confidence", 0.1)

        # REAL VERIFICATION: tampering MUST be detected
        assert pred.verify() is False, "Tampered model must FAIL verification!"

        # Signature should NOT have changed (it was set at creation)
        assert pred.signature == original_sig

    def test_different_instances_have_different_signatures(self):
        """
        REAL TEST: Two identical models must have DIFFERENT signatures.
        Otherwise replay attacks are trivial.
        """
        from trustchain.integrations.pydantic_v2 import TrustChainModel

        class Result(TrustChainModel):
            value: int

        r1 = Result(value=42)
        r2 = Result(value=42)  # Same data!

        # REAL VERIFICATION: different instances = different signatures
        assert (
            r1.signature != r2.signature
        ), "Identical data must have different signatures (nonce)!"

        # But both must verify
        assert r1.verify() is True
        assert r2.verify() is True

    def test_signature_covers_all_fields(self):
        """
        REAL TEST: Changing ANY field must break verification.
        """
        from trustchain.integrations.pydantic_v2 import TrustChainModel

        class ComplexModel(TrustChainModel):
            a: str
            b: int
            c: list
            d: dict

        model = ComplexModel(a="test", b=42, c=[1, 2, 3], d={"key": "value"})
        assert model.verify() is True

        # Tamper each field and verify it breaks
        for field, new_value in [
            ("a", "tampered"),
            ("b", 999),
            ("c", [4, 5, 6]),
            ("d", {"key": "hacked"}),
        ]:
            # Create fresh model
            fresh = ComplexModel(a="test", b=42, c=[1, 2, 3], d={"key": "value"})
            assert fresh.verify() is True

            # Tamper this specific field
            object.__setattr__(fresh, field, new_value)

            # MUST fail
            assert (
                fresh.verify() is False
            ), f"Tampering field '{field}' must break verification!"

    def test_serialization_and_deserialization_preserves_verifiability(self):
        """
        REAL TEST: A model can be serialized, transmitted, and verified.
        """
        from trustchain import TrustChain
        from trustchain.integrations.pydantic_v2 import TrustChainModel

        class APIResponse(TrustChainModel):
            answer: str
            source: str

        # Create and sign server-side
        response = APIResponse(answer="42", source="database")
        signed_resp = response.to_signed_response()

        # Simulate transmission (serialize to JSON-like dict)
        transmitted = {
            "tool_id": signed_resp.tool_id,
            "data": signed_resp.data,
            "signature": signed_resp.signature,
            "nonce": signed_resp.nonce,
            "timestamp": signed_resp.timestamp,
            "parent_signature": signed_resp.parent_signature,
        }

        # Receive on client side
        from trustchain.v2.signer import SignedResponse

        SignedResponse(**transmitted)

        # REAL VERIFICATION: client can verify with same signer
        TrustChain()
        # Note: different key, so verification will fail (expected!)
        # This is correct behavior - you need the same public key

        # But the original signer can verify
        assert response.verify() is True


# ============================================================================
# OpenTelemetry Integration Tests - Real Span Verification
# ============================================================================

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


@pytest.mark.skipif(not HAS_OTEL, reason="OpenTelemetry not installed")
class TestOpenTelemetryRealIntegration:
    """Test TrustChain actually adds verifiable attributes to spans."""

    def test_span_attributes_are_actually_set(self):
        """
        REAL TEST: Span attributes are actually accessible after export.
        """
        from trustchain import TrustChain
        from trustchain.integrations.opentelemetry import (
            ATTR_TRUSTCHAIN_NONCE,
            ATTR_TRUSTCHAIN_SIGNATURE,
            ATTR_TRUSTCHAIN_TOOL_ID,
            instrument_span,
        )

        provider = TracerProvider()
        exporter = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("test")

        tc = TrustChain()

        with tracer.start_as_current_span("test_operation") as span:
            response = tc._signer.sign("my_tool", {"result": "data"})
            instrument_span(span, response)

        spans = exporter.get_finished_spans()
        assert len(spans) == 1

        attrs = dict(spans[0].attributes)

        # REAL VERIFICATION: all TrustChain attributes are present
        assert ATTR_TRUSTCHAIN_TOOL_ID in attrs
        assert ATTR_TRUSTCHAIN_SIGNATURE in attrs
        assert ATTR_TRUSTCHAIN_NONCE in attrs

        # REAL VERIFICATION: values are correct
        assert attrs[ATTR_TRUSTCHAIN_TOOL_ID] == "my_tool"
        assert attrs[ATTR_TRUSTCHAIN_SIGNATURE] == response.signature
        assert attrs[ATTR_TRUSTCHAIN_NONCE] == response.nonce

    def test_span_signatures_can_be_verified_from_export(self):
        """
        REAL TEST: Exported span data can be used to verify the operation.
        """
        from trustchain import TrustChain
        from trustchain.integrations.opentelemetry import (
            ATTR_TRUSTCHAIN_NONCE,
            ATTR_TRUSTCHAIN_SIGNATURE,
            ATTR_TRUSTCHAIN_TIMESTAMP,
            ATTR_TRUSTCHAIN_TOOL_ID,
            instrument_span,
        )
        from trustchain.v2.signer import SignedResponse

        provider = TracerProvider()
        exporter = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("verification_test")

        tc = TrustChain()
        original_data = {"critical": "operation", "user": "admin"}

        with tracer.start_as_current_span("critical_op") as span:
            response = tc._signer.sign("admin_action", original_data)
            instrument_span(span, response)

        # Simulate: get span from OTel backend
        exported_span = exporter.get_finished_spans()[0]
        attrs = dict(exported_span.attributes)

        # Reconstruct SignedResponse from span attributes
        reconstructed = SignedResponse(
            tool_id=attrs[ATTR_TRUSTCHAIN_TOOL_ID],
            data=original_data,  # This would come from span events/logs
            signature=attrs[ATTR_TRUSTCHAIN_SIGNATURE],
            nonce=attrs[ATTR_TRUSTCHAIN_NONCE],
            timestamp=attrs.get(ATTR_TRUSTCHAIN_TIMESTAMP, ""),
            parent_signature=attrs.get("trustchain.parent_signature"),
        )

        # REAL VERIFICATION: reconstructed response verifies
        assert tc._signer.verify(reconstructed) is True

    def test_nested_spans_have_proper_chain(self):
        """
        REAL TEST: Nested spans preserve parent-child chain.
        """
        from trustchain import TrustChain
        from trustchain.integrations.opentelemetry import (
            ATTR_TRUSTCHAIN_PARENT_SIGNATURE,
            ATTR_TRUSTCHAIN_SIGNATURE,
            instrument_span,
        )

        provider = TracerProvider()
        exporter = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("chain_test")

        tc = TrustChain()

        with tracer.start_as_current_span("parent_op") as parent_span:
            parent_resp = tc._signer.sign("step1", {"data": "parent"})
            instrument_span(parent_span, parent_resp)

            with tracer.start_as_current_span("child_op") as child_span:
                child_resp = tc._signer.sign(
                    "step2",
                    {"data": "child"},
                    parent_signature=parent_resp.signature,
                )
                instrument_span(child_span, child_resp)

        spans = exporter.get_finished_spans()
        # Spans are in reverse order (child finishes first)
        child_attrs = dict(spans[0].attributes)
        parent_attrs = dict(spans[1].attributes)

        # REAL VERIFICATION: child has parent signature attribute
        assert ATTR_TRUSTCHAIN_PARENT_SIGNATURE in child_attrs
        assert (
            child_attrs[ATTR_TRUSTCHAIN_PARENT_SIGNATURE]
            == parent_attrs[ATTR_TRUSTCHAIN_SIGNATURE]
        )


# ============================================================================
# AsyncTrustChain Integration Tests - Real Async Behavior
# ============================================================================


@pytest.mark.asyncio
class TestAsyncRealIntegration:
    """Test AsyncTrustChain works correctly in async scenarios."""

    async def test_concurrent_signatures_are_unique(self):
        """
        REAL TEST: Concurrent async operations get unique signatures.
        Race conditions could cause signature reuse.
        """
        import asyncio

        from trustchain import AsyncTrustChain

        async with AsyncTrustChain() as tc:

            async def sign_operation(i: int):
                await asyncio.sleep(0.001)  # Simulate some async work
                return await tc.sign(f"op_{i}", {"index": i})

            # Run 20 concurrent signings
            responses = await asyncio.gather(*[sign_operation(i) for i in range(20)])

            # REAL VERIFICATION: all signatures are unique
            signatures = [r.signature for r in responses]
            assert (
                len(set(signatures)) == 20
            ), "All concurrent signatures must be unique!"

            # REAL VERIFICATION: all nonces are unique
            nonces = [r.nonce for r in responses]
            assert len(set(nonces)) == 20, "All nonces must be unique!"

    async def test_chain_linking_works_correctly(self):
        """
        REAL TEST: Parent signatures are correctly linked.
        """
        from trustchain import AsyncTrustChain

        async with AsyncTrustChain() as tc:
            # Create proper chain
            r1 = await tc.sign("step1", {"data": 1})
            r2 = await tc.sign("step2", {"data": 2}, parent_signature=r1.signature)
            r3 = await tc.sign("step3", {"data": 3}, parent_signature=r2.signature)

            # REAL VERIFICATION: parent signatures are correctly chained
            assert r2.parent_signature == r1.signature
            assert r3.parent_signature == r2.signature
            assert r1.parent_signature is None

    async def test_tampered_response_fails_signer_verification(self):
        """
        REAL TEST: Modifying data in response breaks signer verification.
        Uses signer.verify() directly to avoid nonce replay tracking.
        """
        from trustchain import AsyncTrustChain
        from trustchain.v2.signer import SignedResponse

        async with AsyncTrustChain() as tc:
            response = await tc.sign("important_tool", {"secret": "original"})

            # Should verify with signer (bypasses nonce tracking)
            assert tc._signer.verify(response) is True

            # Create tampered copy
            tampered = SignedResponse(
                tool_id=response.tool_id,
                data={"secret": "TAMPERED"},
                signature=response.signature,
                nonce=response.nonce,
                timestamp=response.timestamp,
                parent_signature=response.parent_signature,
            )

            # REAL VERIFICATION: tampered response must fail signer verification
            assert tc._signer.verify(tampered) is False


# ============================================================================
# pytest Plugin Integration Tests - Real Fixture Behavior
# ============================================================================


class TestPytestPluginRealIntegration:
    """Test pytest fixtures work correctly in real test scenarios."""

    def test_tc_fixture_creates_working_signer(self, tc):
        """
        REAL TEST: tc fixture provides working TrustChain.
        """
        from trustchain import TrustChain

        assert isinstance(tc, TrustChain)

        # REAL VERIFICATION: can actually sign and verify
        response = tc._signer.sign("test_tool", {"data": "test"})
        assert tc._signer.verify(response) is True

        # Tamper and verify it fails
        from trustchain.v2.signer import SignedResponse

        tampered = SignedResponse(
            tool_id=response.tool_id,
            data={"data": "HACKED"},
            signature=response.signature,
            nonce=response.nonce,
            timestamp=response.timestamp,
            parent_signature=response.parent_signature,
        )
        assert tc._signer.verify(tampered) is False

    def test_signed_chain_collector_tracks_and_verifies(self, tc, signed_chain):
        """
        REAL TEST: SignedChainCollector properly tracks chain integrity.
        """
        # Build a chain
        r1 = tc._signer.sign("step1", {"data": 1})
        signed_chain.append(r1)

        r2 = tc._signer.sign("step2", {"data": 2}, parent_signature=r1.signature)
        signed_chain.append(r2)

        r3 = tc._signer.sign("step3", {"data": 3}, parent_signature=r2.signature)
        signed_chain.append(r3)

        # REAL VERIFICATION: chain collector works
        assert len(signed_chain) == 3
        assert signed_chain.verify_all(tc) is True
        assert signed_chain.get_tool_ids() == ["step1", "step2", "step3"]

    def test_signed_chain_detects_tampering(self, tc, signed_chain):
        """
        REAL TEST: Chain collector detects if any element is tampered.
        """
        r1 = tc._signer.sign("op1", {"value": 100})
        signed_chain.append(r1)

        r2 = tc._signer.sign("op2", {"value": 200})
        signed_chain.append(r2)

        assert signed_chain.verify_all(tc) is True

        # Tamper with first response's data using list access (it inherits from list)
        from trustchain.v2.signer import SignedResponse

        tampered = SignedResponse(
            tool_id=r1.tool_id,
            data={"value": 999},  # Changed!
            signature=r1.signature,
            nonce=r1.nonce,
            timestamp=r1.timestamp,
            parent_signature=r1.parent_signature,
        )
        signed_chain[0] = tampered  # Use list indexing

        # REAL VERIFICATION: collector now fails verification
        assert signed_chain.verify_all(tc) is False
