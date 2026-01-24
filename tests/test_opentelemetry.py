"""Tests for OpenTelemetry integration."""

import pytest

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False

pytestmark = pytest.mark.skipif(not HAS_OTEL, reason="OpenTelemetry not installed")

from trustchain import SignedResponse, TrustChain
from trustchain.integrations.opentelemetry import (
    ATTR_TRUSTCHAIN_SIGNATURE,
    ATTR_TRUSTCHAIN_TOOL_ID,
    ATTR_TRUSTCHAIN_VERIFIED,
    TrustChainInstrumentor,
    TrustChainSpanProcessor,
    instrument_span,
    set_trustchain_span_attributes,
)


@pytest.fixture
def otel_provider():
    """Create isolated tracer provider with in-memory exporter."""
    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


class TestTrustChainSpanProcessor:
    """Test span processor."""

    def test_create_processor(self):
        """Test processor creation."""
        processor = TrustChainSpanProcessor()
        assert processor is not None

    def test_processor_with_custom_signer(self):
        """Test processor with custom signer."""
        from trustchain.v2.signer import Signer

        signer = Signer()
        processor = TrustChainSpanProcessor(signer=signer)
        assert processor._signer is signer

    def test_processor_force_flush(self):
        """Test force flush returns True."""
        processor = TrustChainSpanProcessor()
        assert processor.force_flush() is True

    def test_processor_shutdown(self):
        """Test shutdown doesn't error."""
        processor = TrustChainSpanProcessor()
        processor.shutdown()  # Should not raise


class TestInstrumentSpan:
    """Test instrument_span helper."""

    def test_instrument_span_adds_attributes(self, otel_provider):
        """Test instrument_span adds correct attributes."""
        provider, exporter = otel_provider
        tracer = provider.get_tracer("test")
        tc = TrustChain()

        with tracer.start_as_current_span("test_span") as span:
            response = tc._signer.sign("test_tool", {"value": 42})
            instrument_span(span, response)

        spans = exporter.get_finished_spans()
        assert len(spans) == 1

        attrs = dict(spans[0].attributes)
        assert ATTR_TRUSTCHAIN_TOOL_ID in attrs
        assert attrs[ATTR_TRUSTCHAIN_TOOL_ID] == "test_tool"
        assert ATTR_TRUSTCHAIN_SIGNATURE in attrs

    def test_instrument_span_with_parent_sig(self, otel_provider):
        """Test instrument_span with parent signature."""
        provider, exporter = otel_provider
        tracer = provider.get_tracer("test")
        tc = TrustChain()

        with tracer.start_as_current_span("parent_span") as span:
            parent_response = tc._signer.sign("parent_tool", {})

            child_response = tc._signer.sign(
                "child_tool", {"data": 1}, parent_signature=parent_response.signature
            )
            instrument_span(span, child_response)

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)

        assert "trustchain.parent_signature" in attrs


class TestSetAttributes:
    """Test set_trustchain_span_attributes helper."""

    def test_set_attributes(self, otel_provider):
        """Test setting attributes on span."""
        provider, exporter = otel_provider
        tracer = provider.get_tracer("test")

        with tracer.start_as_current_span("test") as span:
            set_trustchain_span_attributes(
                span=span,
                tool_id="my_tool",
                signature="abc123xyz",
                verified=True,
                chain_id="chain-001",
            )

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)

        assert attrs[ATTR_TRUSTCHAIN_TOOL_ID] == "my_tool"
        assert attrs[ATTR_TRUSTCHAIN_VERIFIED] is True

    def test_set_attributes_minimal(self, otel_provider):
        """Test setting minimal attributes."""
        provider, exporter = otel_provider
        tracer = provider.get_tracer("test")

        with tracer.start_as_current_span("minimal") as span:
            set_trustchain_span_attributes(
                span=span,
                tool_id="tool",
                signature="sig",
                verified=False,
            )

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)

        assert attrs[ATTR_TRUSTCHAIN_TOOL_ID] == "tool"
        assert attrs[ATTR_TRUSTCHAIN_VERIFIED] is False


class TestTrustChainInstrumentor:
    """Test auto-instrumentor."""

    def test_instrumentor_creation(self):
        """Test instrumentor creation."""
        instrumentor = TrustChainInstrumentor()
        assert instrumentor is not None
        assert instrumentor._tracer_name == "trustchain"

    def test_instrumentor_custom_tracer_name(self):
        """Test instrumentor with custom tracer name."""
        instrumentor = TrustChainInstrumentor(tracer_name="my_app")
        assert instrumentor._tracer_name == "my_app"

    def test_instrument_and_uninstrument(self):
        """Test instrument/uninstrument cycle."""
        instrumentor = TrustChainInstrumentor()

        instrumentor.instrument()
        assert instrumentor._is_instrumented is True

        instrumentor.uninstrument()
        assert instrumentor._is_instrumented is False

    def test_double_instrument_is_safe(self):
        """Test calling instrument() twice is safe."""
        instrumentor = TrustChainInstrumentor()

        try:
            instrumentor.instrument()
            instrumentor.instrument()  # Should not error
            assert instrumentor._is_instrumented is True
        finally:
            instrumentor.uninstrument()

    def test_double_uninstrument_is_safe(self):
        """Test calling uninstrument() twice is safe."""
        instrumentor = TrustChainInstrumentor()

        instrumentor.instrument()
        instrumentor.uninstrument()
        instrumentor.uninstrument()  # Should not error

        assert instrumentor._is_instrumented is False

    def test_instrumented_sign_returns_response(self):
        """Test instrumented sign still returns SignedResponse."""
        instrumentor = TrustChainInstrumentor()
        instrumentor.instrument()

        try:
            tc = TrustChain()
            result = tc.sign("test", {"value": 123})

            assert isinstance(result, SignedResponse)
            assert result.tool_id == "test"
            assert result.data == {"value": 123}
        finally:
            instrumentor.uninstrument()


class TestCreateTracedTrustchain:
    """Test create_traced_trustchain factory."""

    def test_create_traced_returns_trustchain(self):
        """Test factory returns TrustChain."""
        from trustchain.integrations.opentelemetry import create_traced_trustchain

        # Uninstrument first to reset state
        TrustChainInstrumentor().uninstrument()

        tc = create_traced_trustchain()
        assert isinstance(tc, TrustChain)

        # Cleanup
        TrustChainInstrumentor().uninstrument()

    def test_traced_trustchain_signs_correctly(self):
        """Test traced TrustChain can sign data."""
        from trustchain.integrations.opentelemetry import create_traced_trustchain

        TrustChainInstrumentor().uninstrument()

        tc = create_traced_trustchain()
        result = tc.sign("traced_tool", {"key": "value"})

        assert isinstance(result, SignedResponse)
        assert result.tool_id == "traced_tool"

        TrustChainInstrumentor().uninstrument()
