"""TrustChain FastAPI Integration.

Provides middleware and decorators for automatic response signing in FastAPI applications.

Example:
    from fastapi import FastAPI
    from trustchain import TrustChain
    from trustchain.integrations.fastapi import TrustChainMiddleware, sign_response

    tc = TrustChain()
    app = FastAPI()

    # Option 1: Middleware (signs ALL JSON responses)
    app.add_middleware(TrustChainMiddleware, trustchain=tc)

    # Option 2: Decorator (per-endpoint)
    @app.post("/api/tool")
    @sign_response(tc, "my_tool")
    async def endpoint():
        return {"result": "data"}
"""

import functools
import json
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class TrustChainMiddleware(BaseHTTPMiddleware):
    """ASGI Middleware that automatically signs all JSON responses.

    Args:
        app: The ASGI application
        trustchain: TrustChain instance for signing
        sign_all: If True, sign all JSON responses. If False, only sign
                  responses with X-TrustChain-Sign header. Default: True
        tool_id_header: Header name to specify tool_id. Default: X-TrustChain-Tool
        skip_paths: List of paths to skip signing (e.g., ["/health", "/docs"])
    """

    def __init__(
        self,
        app,
        trustchain,
        sign_all: bool = True,
        tool_id_header: str = "X-TrustChain-Tool",
        skip_paths: Optional[list] = None,
    ):
        super().__init__(app)
        self.trustchain = trustchain
        self.sign_all = sign_all
        self.tool_id_header = tool_id_header
        self.skip_paths = skip_paths or ["/docs", "/openapi.json", "/health", "/redoc"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and sign response if applicable."""
        # Skip certain paths
        if request.url.path in self.skip_paths:
            return await call_next(request)

        response = await call_next(request)

        # Only sign JSON responses
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return response

        # Check if we should sign this response
        should_sign = self.sign_all or request.headers.get("X-TrustChain-Sign")
        if not should_sign:
            return response

        # Get tool_id from header or use path as fallback
        tool_id = request.headers.get(self.tool_id_header) or request.url.path

        # Read response body
        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        try:
            # Parse JSON and sign
            data = json.loads(body)
            signed = self.trustchain.sign(tool_id, data)

            # Return signed response
            return JSONResponse(
                content=signed.to_dict(),
                status_code=response.status_code,
                headers={
                    "X-TrustChain-Signed": "true",
                    "X-TrustChain-Key-ID": self.trustchain.get_key_id(),
                },
            )
        except json.JSONDecodeError:
            # Not valid JSON, return original
            return Response(
                content=body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )


def sign_response(trustchain, tool_id: str):
    """Decorator to sign individual endpoint responses.

    Args:
        trustchain: TrustChain instance
        tool_id: Identifier for this tool/endpoint

    Example:
        @app.post("/api/search")
        @sign_response(tc, "search_api")
        async def search(query: str):
            return {"results": [...]}
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Execute original function
            result = await func(*args, **kwargs)

            # If already a Response, extract data
            if isinstance(result, Response):
                return result

            # Sign the result
            signed = trustchain.sign(tool_id, result)
            return JSONResponse(
                content=signed.to_dict(),
                headers={
                    "X-TrustChain-Signed": "true",
                    "X-TrustChain-Key-ID": trustchain.get_key_id(),
                },
            )

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            if isinstance(result, Response):
                return result
            signed = trustchain.sign(tool_id, result)
            return JSONResponse(
                content=signed.to_dict(),
                headers={
                    "X-TrustChain-Signed": "true",
                    "X-TrustChain-Key-ID": trustchain.get_key_id(),
                },
            )

        # Return appropriate wrapper
        if asyncio_iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def asyncio_iscoroutinefunction(func: Callable) -> bool:
    """Check if function is async."""
    import asyncio
    import inspect

    return asyncio.iscoroutinefunction(func) or inspect.iscoroutinefunction(func)


class TrustChainAPIRouter:
    """Helper to create a FastAPI router with TrustChain integration.

    Example:
        from trustchain.integrations.fastapi import TrustChainAPIRouter

        tc = TrustChain()
        router = TrustChainAPIRouter(tc)

        @router.tool("search")
        async def search(query: str):
            return {"results": [...]}

        # Router can be included in FastAPI app
        app.include_router(router.fastapi_router, prefix="/api")
    """

    def __init__(self, trustchain):
        from fastapi import APIRouter

        self.trustchain = trustchain
        self.fastapi_router = APIRouter()
        self._tools = {}

    def tool(self, tool_id: str, **route_kwargs):
        """Register a tool endpoint.

        Args:
            tool_id: Unique tool identifier
            **route_kwargs: Additional FastAPI route arguments
        """

        def decorator(func: Callable):
            # Register with TrustChain
            tc_tool = self.trustchain.tool(tool_id)(func)
            self._tools[tool_id] = tc_tool

            # Create signed endpoint
            @self.fastapi_router.post(f"/{tool_id}", **route_kwargs)
            @sign_response(self.trustchain, tool_id)
            @functools.wraps(func)
            async def endpoint(**kwargs):
                return (
                    await func(**kwargs)
                    if asyncio_iscoroutinefunction(func)
                    else func(**kwargs)
                )

            return tc_tool

        return decorator

    def get_tools_schema(self, format: str = "openai"):
        """Get OpenAI/Anthropic schema for all registered tools."""
        return self.trustchain.get_tools_schema(format=format)
