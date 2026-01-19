"""Tests for trustchain/v2/server.py - REST API endpoints."""

from unittest.mock import MagicMock, patch

import pytest

# FastAPI test client
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from trustchain.v2.server import app


class TestHealthEndpoint:
    """Test /health endpoint."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_health_returns_ok(self, client):
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_health_includes_version(self, client):
        response = client.get("/health")

        data = response.json()
        assert "version" in data


class TestPublicKeyEndpoint:
    """Test /public-key endpoint."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_get_public_key(self, client):
        response = client.get("/public-key")

        assert response.status_code == 200
        data = response.json()
        assert "public_key" in data
        assert "key_id" in data

    def test_public_key_is_base64(self, client):
        response = client.get("/public-key")

        data = response.json()
        # Base64 characters only
        import re

        assert re.match(r"^[A-Za-z0-9+/=]+$", data["public_key"])


class TestSignEndpoint:
    """Test POST /sign endpoint."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_sign_returns_signature(self, client):
        response = client.post(
            "/sign", json={"tool_id": "test_tool", "data": {"value": 42}}
        )

        assert response.status_code == 200
        data = response.json()
        assert "signature" in data
        assert "nonce" in data
        assert "timestamp" in data

    def test_sign_with_complex_data(self, client):
        response = client.post(
            "/sign",
            json={
                "tool_id": "complex_tool",
                "data": {
                    "nested": {"key": "value"},
                    "array": [1, 2, 3],
                    "number": 123.456,
                },
            },
        )

        assert response.status_code == 200

    def test_sign_missing_tool_id(self, client):
        response = client.post("/sign", json={"data": {"value": 1}})

        # Should fail validation
        assert response.status_code == 422

    def test_sign_empty_data(self, client):
        response = client.post("/sign", json={"tool_id": "empty_tool", "data": {}})

        assert response.status_code == 200


class TestVerifyEndpoint:
    """Test POST /verify endpoint."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_verify_valid_signature(self, client):
        # First sign
        sign_response = client.post(
            "/sign", json={"tool_id": "verify_test", "data": {"test": "data"}}
        )
        signed_data = sign_response.json()

        # Then verify
        verify_response = client.post(
            "/verify",
            json={
                "tool_id": "verify_test",
                "data": {"test": "data"},
                "signature": signed_data["signature"],
                "signature_id": signed_data["signature_id"],
                "nonce": signed_data["nonce"],
                "timestamp": signed_data["timestamp"],
            },
        )

        assert verify_response.status_code == 200
        result = verify_response.json()
        assert result["valid"] is True

    def test_verify_invalid_signature(self, client):
        response = client.post(
            "/verify",
            json={
                "tool_id": "test",
                "data": {"test": "data"},
                "signature": "invalid_signature_here",
                "signature_id": "fake-sig-id",
                "nonce": "some-nonce",
                "timestamp": 1234567890,
            },
        )

        assert response.status_code == 200
        result = response.json()
        assert result["valid"] is False

    def test_verify_tampered_data(self, client):
        # First sign
        sign_response = client.post(
            "/sign", json={"tool_id": "tamper_test", "data": {"original": "data"}}
        )
        signed_data = sign_response.json()

        # Verify with different data
        verify_response = client.post(
            "/verify",
            json={
                "tool_id": "tamper_test",
                "data": {"tampered": "data"},  # Different data
                "signature": signed_data["signature"],
                "signature_id": signed_data["signature_id"],
                "nonce": signed_data["nonce"],
                "timestamp": signed_data["timestamp"],
            },
        )

        result = verify_response.json()
        assert result["valid"] is False


class TestAPIErrorHandling:
    """Test API error handling."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_invalid_json(self, client):
        response = client.post(
            "/sign",
            content="not valid json",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 422

    def test_method_not_allowed(self, client):
        response = client.get("/sign")

        assert response.status_code == 405

    def test_not_found(self, client):
        response = client.get("/nonexistent")

        assert response.status_code == 404
