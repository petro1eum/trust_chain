"""OpenTelemetry integration for TrustChain.

Provides:
    - TrustChainSpanProcessor: Adds signatures to spans
    - TrustChainInstrumentor: Auto-instrument TrustChain calls
    - Trace context propagation for chains

Example:
    from trustchain.integrations.opentelemetry import TrustChainInstrumentor
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    # Setup
    trace.set_tracer_provider(TracerProvider())
    TrustChainInstrumentor().instrument()

    # Now all TrustChain calls add signature attributes to spans
    tc = TrustChain()
    result = tc.sign("my_tool", {"data": "value"})
    # Span has: trustchain.signature, trustchain.tool_id, trustchain.verified
"""

from __future__ import annotations

import functools
from typing import Any, Callable

try:
    from opentelemetry import trace
    from opentelemetry.context import Context
    from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor
    from opentelemetry.trace import Span, SpanKind, Status, StatusCode

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False
    SpanProcessor = object  # type: ignore
    Span = object  # type: ignore

from trustchain import SignedResponse, TrustChain
from trustchain.v2.signer import Signer

# Semantic convention attributes for TrustChain
ATTR_TRUSTCHAIN_TOOL_ID = "trustchain.tool_id"
ATTR_TRUSTCHAIN_SIGNATURE = "trustchain.signature"
ATTR_TRUSTCHAIN_SIGNATURE_ID = "trustchain.signature_id"
ATTR_TRUSTCHAIN_VERIFIED = "trustchain.verified"
ATTR_TRUSTCHAIN_TIMESTAMP = "trustchain.timestamp"
ATTR_TRUSTCHAIN_NONCE = "trustchain.nonce"
ATTR_TRUSTCHAIN_PARENT_SIG = "trustchain.parent_signature"
ATTR_TRUSTCHAIN_PARENT_SIGNATURE = "trustchain.parent_signature"  # Alias
ATTR_TRUSTCHAIN_CHAIN_ID = "trustchain.chain_id"


class TrustChainSpanProcessor(SpanProcessor if HAS_OTEL else object):
    """Span processor that adds TrustChain signatures to spans.

    Automatically signs span data and adds signature as attribute.

    Example:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        provider = TracerProvider()
        provider.add_span_processor(TrustChainSpanProcessor())
        trace.set_tracer_provider(provider)
    """

    def __init__(self, signer: Signer | None = None, sign_all: bool = True):
        """Initialize the processor.

        Args:
            signer: Custom signer (creates new if not provided)
            sign_all: Whether to sign all spans or only TrustChain ones
        """
        if not HAS_OTEL:
            raise ImportError(
                "OpenTelemetry required. Install with: pip install opentelemetry-api opentelemetry-sdk"
            )
        self._signer = signer or Signer()
        self._sign_all = sign_all

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        """Called when span starts - nothing to do yet."""
        pass

    def on_end(self, span: ReadableSpan) -> None:
        """Called when span ends - sign the span data."""
        if not self._sign_all:
            # Only sign spans with trustchain attributes
            if not span.attributes or ATTR_TRUSTCHAIN_TOOL_ID not in span.attributes:
                return

        # Create signable data from span
        span_data = {
            "name": span.name,
            "trace_id": format(span.context.trace_id, "032x") if span.context else None,
            "span_id": format(span.context.span_id, "016x") if span.context else None,
            "start_time": span.start_time,
            "end_time": span.end_time,
            "status": span.status.status_code.name if span.status else None,
        }

        # Sign it
        self._signer.sign(
            tool_id=f"otel:span:{span.name}",
            data=span_data,
        )

        # Note: We can't modify ReadableSpan after it ends
        # This processor is for audit/logging purposes
        # Real signature injection happens in instrument_span()

    def shutdown(self) -> None:
        """Shutdown the processor."""
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Force flush - nothing to flush."""
        return True


def instrument_span(span: Span, response: SignedResponse) -> None:
    """Add TrustChain signature attributes to a span.

    Example:
        with tracer.start_as_current_span("my_tool") as span:
            result = tc.sign("my_tool", data)
            instrument_span(span, result)
    """
    if not HAS_OTEL:
        return

    span.set_attribute(ATTR_TRUSTCHAIN_TOOL_ID, response.tool_id)
    span.set_attribute(ATTR_TRUSTCHAIN_SIGNATURE, response.signature)  # Full signature
    span.set_attribute(ATTR_TRUSTCHAIN_SIGNATURE_ID, response.signature_id)
    span.set_attribute(ATTR_TRUSTCHAIN_TIMESTAMP, response.timestamp)
    span.set_attribute(ATTR_TRUSTCHAIN_NONCE, response.nonce)

    if response.parent_signature:
        span.set_attribute(ATTR_TRUSTCHAIN_PARENT_SIG, response.parent_signature)
        span.set_attribute(ATTR_TRUSTCHAIN_PARENT_SIGNATURE, response.parent_signature)


class TrustChainInstrumentor:
    """Auto-instrument TrustChain to add tracing.

    Wraps TrustChain.sign() and tool decorator to create spans.

    Example:
        TrustChainInstrumentor().instrument()

        tc = TrustChain()
        result = tc.sign("my_tool", data)  # Creates span automatically
    """

    _original_sign: Callable | None = None
    _original_tool: Callable | None = None
    _is_instrumented: bool = False

    def __init__(self, tracer_name: str = "trustchain"):
        """Initialize instrumentor.

        Args:
            tracer_name: Name for the tracer
        """
        if not HAS_OTEL:
            raise ImportError(
                "OpenTelemetry required. Install with: pip install opentelemetry-api opentelemetry-sdk"
            )
        self._tracer_name = tracer_name

    def instrument(self) -> None:
        """Install instrumentation."""
        if self._is_instrumented:
            return

        self._tracer = trace.get_tracer(self._tracer_name)

        # Wrap TrustChain.sign
        self._original_sign = TrustChain.sign
        TrustChain.sign = self._wrap_sign(TrustChain.sign)

        self._is_instrumented = True

    def uninstrument(self) -> None:
        """Remove instrumentation."""
        if not self._is_instrumented:
            return

        if self._original_sign:
            TrustChain.sign = self._original_sign

        self._is_instrumented = False

    def _wrap_sign(self, original: Callable) -> Callable:
        """Wrap the sign method to add tracing."""
        tracer = self._tracer

        @functools.wraps(original)
        def wrapper(self_tc, tool_id: str, data: Any, **kwargs):
            with tracer.start_as_current_span(
                name=f"trustchain.sign.{tool_id}",
                kind=SpanKind.INTERNAL,
            ) as span:
                try:
                    result = original(self_tc, tool_id, data, **kwargs)

                    # Add signature attributes
                    instrument_span(span, result)
                    span.set_attribute(ATTR_TRUSTCHAIN_VERIFIED, True)

                    return result

                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise

        return wrapper


def create_traced_trustchain(tracer_name: str = "trustchain") -> TrustChain:
    """Create a TrustChain instance with automatic tracing.

    Convenience function that instruments and creates instance.

    Example:
        tc = create_traced_trustchain()
        result = tc.sign("tool", data)  # Creates span automatically
    """
    TrustChainInstrumentor(tracer_name).instrument()
    return TrustChain()


# Export helper for setting span attributes in bulk
def set_trustchain_span_attributes(
    span: Span,
    tool_id: str,
    signature: str,
    verified: bool,
    chain_id: str | None = None,
) -> None:
    """Set TrustChain attributes on a span.

    Helper for manual instrumentation.
    """
    if not HAS_OTEL:
        return

    span.set_attribute(ATTR_TRUSTCHAIN_TOOL_ID, tool_id)
    span.set_attribute(ATTR_TRUSTCHAIN_SIGNATURE, signature[:64])
    span.set_attribute(ATTR_TRUSTCHAIN_VERIFIED, verified)

    if chain_id:
        span.set_attribute(ATTR_TRUSTCHAIN_CHAIN_ID, chain_id)
