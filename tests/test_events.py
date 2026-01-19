"""Tests for trustchain/v2/events.py - CloudEvents format."""

import json
from datetime import datetime

import pytest

from trustchain import TrustChain
from trustchain.v2.events import TrustEvent


class TestTrustEvent:
    """Test TrustEvent dataclass."""

    def test_create_event(self):
        event = TrustEvent(source="/agent/my-bot", subject="weather", data={"temp": 22})

        assert event.specversion == "1.0"
        assert event.type == "ai.tool.response.v1"
        assert event.source == "/agent/my-bot"
        assert event.data == {"temp": 22}

    def test_event_has_id(self):
        event = TrustEvent(source="/test")

        assert event.id is not None
        assert len(event.id) > 0

    def test_event_has_time(self):
        event = TrustEvent(source="/test")

        assert event.time is not None
        # Should be ISO format
        assert "T" in event.time


class TestTrustEventFromSignedResponse:
    """Test creating TrustEvent from SignedResponse."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_from_signed_response(self, tc):
        @tc.tool("weather")
        def get_weather(city: str) -> dict:
            return {"city": city, "temp": 22}

        result = get_weather("Moscow")
        event = TrustEvent.from_signed_response(result, source="/my-agent")

        assert event.source == "/my-agent"
        assert event.subject == "weather"
        assert event.trustchain_signature == result.signature
        assert (
            event.data["result"]["city"] == "Moscow"
        )  # Data is wrapped in 'result' key

    def test_with_chain_id(self, tc):
        result = tc._signer.sign("test", {"value": 1})
        event = TrustEvent.from_signed_response(
            result, source="/agent", chain_id="chain-123"
        )

        assert event.trustchain_chain_id == "chain-123"

    def test_with_parent_signature(self, tc):
        step1 = tc._signer.sign("step1", {"a": 1})
        step2 = tc._signer.sign("step2", {"b": 2}, parent_signature=step1.signature)

        event = TrustEvent.from_signed_response(step2, source="/agent")

        assert event.trustchain_parent_signature == step1.signature


class TestTrustEventSerialization:
    """Test TrustEvent serialization methods."""

    def test_to_dict(self):
        event = TrustEvent(source="/test", data={"key": "value"})

        d = event.to_dict()

        assert isinstance(d, dict)
        assert d["source"] == "/test"
        assert d["data"] == {"key": "value"}
        assert d["specversion"] == "1.0"

    def test_to_json(self):
        event = TrustEvent(source="/test", data={"key": "value"})

        json_str = event.to_json()

        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["source"] == "/test"

    def test_to_kafka_headers(self):
        event = TrustEvent(
            source="/test", trustchain_signature="abc123", trustchain_key_id="key-456"
        )

        headers = event.to_kafka_headers()

        assert isinstance(headers, list)
        # Each header is a tuple (key, bytes_value)
        header_dict = {k: v.decode() if isinstance(v, bytes) else v for k, v in headers}
        assert header_dict["ce_source"] == "/test"
        # Kafka headers use truncated signature with different key
        assert "trustchain_sig" in header_dict

    def test_json_roundtrip(self):
        event = TrustEvent(
            source="/agent/bot",
            subject="tool_call",
            data={"result": 42},
            trustchain_signature="sig123",
        )

        json_str = event.to_json()
        parsed = json.loads(json_str)

        assert parsed["source"] == "/agent/bot"
        assert parsed["subject"] == "tool_call"
        assert parsed["data"]["result"] == 42
        # Note: to_dict uses 'trustchainsignature' without underscore
        assert parsed["trustchainsignature"] == "sig123"


class TestCloudEventsCompliance:
    """Test CloudEvents v1.0 specification compliance."""

    def test_required_attributes(self):
        event = TrustEvent(source="/test")
        d = event.to_dict()

        # Required by CloudEvents 1.0
        assert "specversion" in d
        assert "type" in d
        assert "source" in d
        assert "id" in d

    def test_specversion(self):
        event = TrustEvent(source="/test")
        assert event.specversion == "1.0"

    def test_type_format(self):
        event = TrustEvent(source="/test")
        # Should be reverse-DNS style
        assert "." in event.type
        assert event.type == "ai.tool.response.v1"

    def test_source_is_uri(self):
        event = TrustEvent(source="/agent/my-bot/tool/weather")
        # Source should be URI-like
        assert event.source.startswith("/")

    def test_time_is_rfc3339(self):
        event = TrustEvent(source="/test")
        # Should contain T separator for RFC 3339
        assert "T" in event.time
        # Should be parseable
        # ISO format should work
        assert ":" in event.time
