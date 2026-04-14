"""Tests for TrustChain FastAPI Integration (Phase 16.1)."""

import pytest

# Skip if FastAPI/Starlette not installed
pytest.importorskip("fastapi")
pytest.importorskip("starlette")

from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

from trustchain import TrustChain, TrustChainConfig
from trustchain.integrations.fastapi import (
    TrustChainAPIRouter,
    TrustChainMiddleware,
    sign_response,
)


class TestFastAPIMiddleware:
    """Test suite for FastAPI middleware."""

    def test_middleware_signs_json_responses(self):
        """Test middleware automatically signs JSON responses."""
        from fastapi import FastAPI

        tc = TrustChain(TrustChainConfig(enable_nonce=False))
        app = FastAPI()
        app.add_middleware(TrustChainMiddleware, trustchain=tc)

        @app.get("/api/test")
        def test_endpoint():
            return {"result": "data"}

        client = TestClient(app)
        response = client.get("/api/test")

        assert response.status_code == 200
        data = response.json()

        # Should be signed response format
        assert "signature" in data
        assert "tool_id" in data
        assert data["data"] == {"result": "data"}

    def test_middleware_adds_headers(self):
        """Test middleware adds TrustChain headers."""
        from fastapi import FastAPI

        tc = TrustChain()
        app = FastAPI()
        app.add_middleware(TrustChainMiddleware, trustchain=tc)

        @app.get("/api/test")
        def test_endpoint():
            return {"key": "value"}

        client = TestClient(app)
        response = client.get("/api/test")

        assert response.headers.get("X-TrustChain-Signed") == "true"
        assert "X-TrustChain-Key-ID" in response.headers

    def test_middleware_skips_excluded_paths(self):
        """Test middleware skips configured paths."""
        from fastapi import FastAPI

        tc = TrustChain()
        app = FastAPI()
        app.add_middleware(
            TrustChainMiddleware,
            trustchain=tc,
            skip_paths=["/health", "/docs", "/openapi.json", "/redoc"],
        )

        @app.get("/health")
        def health():
            return {"status": "ok"}

        client = TestClient(app)
        response = client.get("/health")

        data = response.json()
        # Should NOT be signed (raw response)
        assert "signature" not in data
        assert data == {"status": "ok"}

    def test_middleware_skip_non_json(self):
        """Test middleware skips non-JSON responses."""
        from fastapi import FastAPI
        from fastapi.responses import PlainTextResponse

        tc = TrustChain()
        app = FastAPI()
        app.add_middleware(TrustChainMiddleware, trustchain=tc)

        @app.get("/text")
        def text_endpoint():
            return PlainTextResponse("Hello, World!")

        client = TestClient(app)
        response = client.get("/text")

        assert response.text == "Hello, World!"

    def test_middleware_sign_all_false(self):
        """sign_all=False: no signing unless X-TrustChain-Sign is an explicit opt-in value."""
        from fastapi import FastAPI

        tc = TrustChain()
        app = FastAPI()
        app.add_middleware(TrustChainMiddleware, trustchain=tc, sign_all=False)

        @app.get("/api/optional")
        def optional_endpoint():
            return {"data": "test"}

        client = TestClient(app)

        response = client.get("/api/optional")
        assert response.headers.get("X-TrustChain-Signed") is None
        assert response.json() == {"data": "test"}

        # Misleading header values must NOT opt in (regression: these strings are truthy in Python)
        for bad in ("0", "false", "no", "off", "anything"):
            r = client.get("/api/optional", headers={"X-TrustChain-Sign": bad})
            assert r.headers.get("X-TrustChain-Signed") is None, bad
            assert r.json() == {"data": "test"}

        # Explicit opt-in still signs
        r = client.get("/api/optional", headers={"X-TrustChain-Sign": "true"})
        assert r.headers.get("X-TrustChain-Signed") == "true"
        body = r.json()
        assert "signature" in body
        assert body["data"] == {"data": "test"}


class TestSignResponseDecorator:
    """Test suite for @sign_response decorator."""

    def test_decorator_signs_response(self):
        """Test decorator signs endpoint response."""
        from fastapi import FastAPI

        tc = TrustChain(TrustChainConfig(enable_nonce=False))
        app = FastAPI()

        @app.post("/api/search")
        @sign_response(tc, "search_tool")
        async def search(query: str = "test"):
            return {"results": [1, 2, 3], "query": query}

        client = TestClient(app)
        response = client.post("/api/search?query=hello")

        assert response.status_code == 200
        data = response.json()

        assert "signature" in data
        assert data["tool_id"] == "search_tool"
        assert data["data"]["query"] == "hello"

    def test_decorator_adds_headers(self):
        """Test decorator adds correct headers."""
        from fastapi import FastAPI

        tc = TrustChain()
        app = FastAPI()

        @app.get("/api/info")
        @sign_response(tc, "info_tool")
        async def get_info():
            return {"info": "test"}

        client = TestClient(app)
        response = client.get("/api/info")

        assert response.headers.get("X-TrustChain-Signed") == "true"
        assert response.headers.get("X-TrustChain-Key-ID") == tc.get_key_id()


class TestTrustChainAPIRouter:
    """Test suite for TrustChainAPIRouter."""

    def test_router_tool_decorator(self):
        """Test router.tool() decorator registers and signs."""
        from fastapi import FastAPI

        tc = TrustChain(TrustChainConfig(enable_nonce=False))
        router = TrustChainAPIRouter(tc)

        @router.tool("add")
        def add(a: int = 1, b: int = 2):
            return {"sum": a + b}

        app = FastAPI()
        app.include_router(router.fastapi_router, prefix="/tools")

        client = TestClient(app)
        response = client.post("/tools/add?a=5&b=3")

        assert response.status_code == 200
        data = response.json()

        assert "signature" in data
        assert data["tool_id"] == "add"

    def test_router_get_tools_schema(self):
        """Test getting tools schema from router."""
        tc = TrustChain()
        router = TrustChainAPIRouter(tc)

        @router.tool("calculator")
        def calculate(x: int, y: int) -> dict:
            """Calculate sum of x and y."""
            return {"result": x + y}

        schemas = router.get_tools_schema(format="openai")
        assert len(schemas) >= 1
