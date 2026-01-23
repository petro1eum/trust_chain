"""Tests for TrustChain Flask Integration (Phase 16.1)."""

import pytest

# Skip if Flask not installed
flask = pytest.importorskip("flask")

from trustchain import TrustChain, TrustChainConfig
from trustchain.integrations.flask import (
    TrustChainFlask,
    get_public_key_endpoint,
    sign_response,
)


class TestFlaskExtension:
    """Test suite for Flask extension."""

    def test_extension_initialization(self):
        """Test Flask extension initializes correctly."""
        app = flask.Flask(__name__)
        tc = TrustChain()

        ext = TrustChainFlask(app, trustchain=tc)

        assert "trustchain" in app.extensions
        assert app.extensions["trustchain"] == ext

    def test_extension_delayed_init(self):
        """Test delayed initialization with init_app."""
        app = flask.Flask(__name__)
        tc = TrustChain()

        ext = TrustChainFlask(trustchain=tc)
        ext.init_app(app)

        assert "trustchain" in app.extensions


class TestFlaskSignResponse:
    """Test suite for @sign_response decorator."""

    def test_decorator_signs_response(self):
        """Test decorator signs endpoint response."""
        app = flask.Flask(__name__)
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        @app.route("/api/test")
        @sign_response(tc, "test_tool")
        def test_endpoint():
            return {"result": "data"}

        with app.test_client() as client:
            response = client.get("/api/test")

            assert response.status_code == 200
            data = response.get_json()

            assert "signature" in data
            assert data["tool_id"] == "test_tool"
            assert data["data"] == {"result": "data"}

    def test_decorator_adds_headers(self):
        """Test decorator adds TrustChain headers."""
        app = flask.Flask(__name__)
        tc = TrustChain()

        @app.route("/api/info")
        @sign_response(tc, "info_tool")
        def info():
            return {"info": "test"}

        with app.test_client() as client:
            response = client.get("/api/info")

            assert response.headers.get("X-TrustChain-Signed") == "true"
            assert "X-TrustChain-Key-ID" in response.headers

    def test_decorator_with_post(self):
        """Test decorator works with POST endpoints."""
        app = flask.Flask(__name__)
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        @app.route("/api/create", methods=["POST"])
        @sign_response(tc, "create_tool")
        def create():
            return {"created": True, "id": 123}

        with app.test_client() as client:
            response = client.post("/api/create")

            assert response.status_code == 200
            data = response.get_json()

            assert data["tool_id"] == "create_tool"
            assert data["data"]["created"] is True


class TestPublicKeyEndpoint:
    """Test suite for public key endpoint."""

    def test_public_key_endpoint(self):
        """Test public key endpoint returns correct data."""
        app = flask.Flask(__name__)
        tc = TrustChain()

        endpoint = get_public_key_endpoint(tc)
        app.add_url_rule("/api/trustchain/public-key", "public_key", endpoint)

        with app.test_client() as client:
            response = client.get("/api/trustchain/public-key")

            assert response.status_code == 200
            data = response.get_json()

            assert "public_key" in data
            assert "key_id" in data
            assert data["algorithm"] == "ed25519"
            assert data["key_id"] == tc.get_key_id()


class TestFlaskWithSession:
    """Test Flask integration with TrustChain sessions."""

    def test_session_in_flask_endpoint(self):
        """Test using TrustChain session in Flask endpoint."""
        app = flask.Flask(__name__)
        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        @app.route("/api/workflow")
        def workflow():
            with tc.session("flask_workflow") as session:
                session.sign("step1", {"action": "start"})
                session.sign("step2", {"action": "process"})

                chain = session.get_chain()
                return flask.jsonify(
                    {"steps": len(chain), "valid": session.verify_chain()}
                )

        with app.test_client() as client:
            response = client.get("/api/workflow")

            assert response.status_code == 200
            data = response.get_json()

            assert data["steps"] == 2
            assert data["valid"] is True
