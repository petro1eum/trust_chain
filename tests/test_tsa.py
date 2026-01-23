"""Tests for TSA (Timestamp Authority) integration."""

import base64
import hashlib
import time
from unittest.mock import Mock, patch

import pytest

from trustchain.v2.tsa import (
    TSA_PROVIDERS,
    TSAClient,
    TSAError,
    TSAResponse,
    TSAVerifyResult,
    get_tsa_client,
)


class TestTSAResponse:
    """Tests for TSAResponse dataclass."""

    def test_to_dict(self):
        """Test TSAResponse serialization."""
        response = TSAResponse(
            token="abc123",
            timestamp=1234567890.0,
            data_hash="hash123",
            tsa_url="https://freetsa.org/tsr",
            hash_algorithm="sha256",
            serial_number="serial123",
        )

        result = response.to_dict()

        assert result["token"] == "abc123"
        assert result["timestamp"] == 1234567890.0
        assert result["data_hash"] == "hash123"
        assert result["tsa_url"] == "https://freetsa.org/tsr"
        assert result["hash_algorithm"] == "sha256"
        assert result["serial_number"] == "serial123"

    def test_from_dict(self):
        """Test TSAResponse deserialization."""
        data = {
            "token": "xyz789",
            "timestamp": 9876543210.0,
            "data_hash": "hash789",
            "tsa_url": "https://digicert.com/tsr",
        }

        response = TSAResponse.from_dict(data)

        assert response.token == "xyz789"
        assert response.timestamp == 9876543210.0
        assert response.data_hash == "hash789"
        assert response.tsa_url == "https://digicert.com/tsr"
        assert response.hash_algorithm == "sha256"  # default


class TestTSAVerifyResult:
    """Tests for TSAVerifyResult dataclass."""

    def test_valid_result(self):
        """Test valid verification result."""
        result = TSAVerifyResult(
            is_valid=True,
            timestamp=time.time(),
            tsa_url="https://freetsa.org/tsr",
        )

        assert result.is_valid is True
        assert result.error is None

    def test_invalid_result(self):
        """Test invalid verification result."""
        result = TSAVerifyResult(
            is_valid=False,
            error="Hash mismatch",
        )

        assert result.is_valid is False
        assert result.error == "Hash mismatch"

    def test_to_dict(self):
        """Test result serialization."""
        result = TSAVerifyResult(is_valid=True, timestamp=123.0)
        data = result.to_dict()

        assert data["is_valid"] is True
        assert data["timestamp"] == 123.0


class TestTSAClient:
    """Tests for TSAClient."""

    def test_init_requires_requests(self):
        """Test that requests library is required."""
        with patch("trustchain.v2.tsa.HAS_REQUESTS", False):
            with pytest.raises(ImportError, match="requests library required"):
                TSAClient()

    def test_build_timestamp_request(self):
        """Test building RFC 3161 timestamp request."""
        client = TSAClient()
        data_hash = hashlib.sha256(b"test data").digest()

        request = client._build_timestamp_request(data_hash)

        # Should start with ASN.1 SEQUENCE tag
        assert request[0] == 0x30
        # Should contain the hash
        assert data_hash in request

    def test_verify_timestamp_hash_mismatch(self):
        """Test verification fails on hash mismatch."""
        client = TSAClient()

        response = TSAResponse(
            token=base64.b64encode(b"x" * 200).decode(),
            timestamp=time.time(),
            data_hash=base64.b64encode(b"wrong hash").decode(),
            tsa_url="https://freetsa.org/tsr",
        )

        result = client.verify_timestamp(response, "different data")

        assert result.is_valid is False
        assert "mismatch" in result.error.lower()

    def test_verify_timestamp_token_too_short(self):
        """Test verification fails on short token."""
        client = TSAClient()

        data = "test data"
        data_hash = hashlib.sha256(data.encode()).digest()

        response = TSAResponse(
            token=base64.b64encode(b"short").decode(),
            timestamp=time.time(),
            data_hash=base64.b64encode(data_hash).decode(),
            tsa_url="https://freetsa.org/tsr",
        )

        result = client.verify_timestamp(response, data)

        assert result.is_valid is False
        assert "too short" in result.error.lower()

    @patch("trustchain.v2.tsa.requests.post")
    def test_get_timestamp_success(self, mock_post):
        """Test successful timestamp request."""
        # Mock response with valid-looking ASN.1 data
        mock_response = Mock()
        mock_response.content = bytes([0x30, 0x82, 0x01, 0x00]) + b"x" * 256
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = TSAClient()
        response = client.get_timestamp("test data")

        assert response.token is not None
        assert response.tsa_url == "https://freetsa.org/tsr"
        assert response.data_hash is not None
        mock_post.assert_called_once()

    @patch("trustchain.v2.tsa.requests.post")
    def test_get_timestamp_network_error(self, mock_post):
        """Test timestamp request handles network errors."""
        import requests

        mock_post.side_effect = requests.RequestException("Connection failed")

        client = TSAClient()

        with pytest.raises(TSAError, match="TSA request failed"):
            client.get_timestamp("test data")

    @patch("trustchain.v2.tsa.requests.post")
    def test_get_timestamp_for_hash(self, mock_post):
        """Test timestamp request for pre-computed hash."""
        mock_response = Mock()
        mock_response.content = bytes([0x30, 0x82, 0x01, 0x00]) + b"x" * 256
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = TSAClient()
        data_hash = hashlib.sha256(b"test").digest()

        response = client.get_timestamp_for_hash(data_hash)

        assert response.token is not None

    def test_get_timestamp_for_hash_wrong_length(self):
        """Test timestamp request rejects wrong hash length."""
        client = TSAClient()

        with pytest.raises(ValueError, match="32 bytes"):
            client.get_timestamp_for_hash(b"wrong length")


class TestGetTSAClient:
    """Tests for get_tsa_client helper."""

    def test_known_provider(self):
        """Test getting client for known provider."""
        client = get_tsa_client("freetsa")
        assert client.url == TSA_PROVIDERS["freetsa"]

    def test_custom_url(self):
        """Test getting client with custom URL."""
        url = "https://custom.tsa.example.com/tsr"
        client = get_tsa_client(url)
        assert client.url == url

    def test_unknown_provider(self):
        """Test unknown provider raises error."""
        with pytest.raises(ValueError, match="Unknown TSA provider"):
            get_tsa_client("unknown_provider")


class TestTSAProviders:
    """Tests for TSA provider list."""

    def test_providers_defined(self):
        """Test that known providers are defined."""
        assert "freetsa" in TSA_PROVIDERS
        assert "digicert" in TSA_PROVIDERS
        assert "sectigo" in TSA_PROVIDERS

    def test_providers_are_urls(self):
        """Test that all providers have valid URLs."""
        for name, url in TSA_PROVIDERS.items():
            assert url.startswith("http"), f"{name} URL should start with http"


# Integration test - skip if no network
@pytest.mark.skip(reason="Requires network access to real TSA")
class TestTSAIntegration:
    """Integration tests with real TSA servers."""

    def test_freetsa_timestamp(self):
        """Test getting timestamp from FreeTSA."""
        client = get_tsa_client("freetsa")

        response = client.get_timestamp("integration test data")

        assert response.token is not None
        assert len(response.token) > 100
        assert response.tsa_url == "https://freetsa.org/tsr"

    def test_digicert_timestamp(self):
        """Test getting timestamp from DigiCert."""
        client = get_tsa_client("digicert")

        response = client.get_timestamp("integration test data")

        assert response.token is not None
