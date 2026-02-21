"""FastAPI REST API server for TrustChain.

Provides HTTP endpoints for signing and verification:
- POST /sign - Sign data with a tool
- POST /verify - Verify a signed response
- GET /health - Health check
- GET /metrics - Prometheus metrics (if enabled)

Usage:
    uvicorn trustchain.v2.server:app --port 8000

    # Or programmatically
    from trustchain.v2.server import create_app
    app = create_app(enable_metrics=True)
"""

from typing import Any, Dict, Optional

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import PlainTextResponse
    from pydantic import BaseModel

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from .config import TrustChainConfig
from .core import TrustChain
from .signer import SignedResponse

# Request/Response models
if HAS_FASTAPI:

    class SignRequest(BaseModel):
        """Request body for /sign endpoint."""

        tool_id: str
        data: Dict[str, Any]

    class SignResponse(BaseModel):
        """Response from /sign endpoint."""

        tool_id: str
        data: Any
        signature: str
        signature_id: str
        timestamp: float
        nonce: Optional[str] = None

    class VerifyRequest(BaseModel):
        """Request body for /verify endpoint."""

        tool_id: str
        data: Any
        signature: str
        signature_id: str
        timestamp: float
        nonce: Optional[str] = None

    class VerifyResponse(BaseModel):
        """Response from /verify endpoint."""

        valid: bool
        error: Optional[str] = None

    class HealthResponse(BaseModel):
        """Response from /health endpoint."""

        status: str
        version: str
        key_id: str
        metrics_enabled: bool
        nonce_backend: str


def create_app(config: Optional[TrustChainConfig] = None, **config_kwargs) -> "FastAPI":
    """Create FastAPI application with TrustChain integration.

    Args:
        config: TrustChainConfig instance
        **config_kwargs: Config options passed to TrustChainConfig

    Returns:
        FastAPI application
    """
    if not HAS_FASTAPI:
        raise ImportError(
            "FastAPI support requires 'fastapi' package. "
            "Install with: pip install fastapi uvicorn"
        )

    # Create config
    if config is None:
        config = TrustChainConfig(**config_kwargs)

    # Create TrustChain and FastAPI app
    tc = TrustChain(config)
    app = FastAPI(
        title="TrustChain API",
        description="Cryptographically signed AI tool responses",
        version="2.0.0",
    )

    # Store TrustChain instance in app state
    app.state.trustchain = tc
    app.state.config = config

    @app.post("/sign", response_model=SignResponse)
    async def sign(request: SignRequest) -> SignResponse:
        """Sign data and return a cryptographically signed response.

        The signature proves that this data was created by this server
        and has not been tampered with.
        """
        try:
            # Create a dynamic tool if not exists
            if request.tool_id not in tc._tools:
                # Register a simple pass-through tool
                @tc.tool(request.tool_id)
                def dynamic_tool(data: Any) -> Any:
                    return data

            # Sign the data
            nonce = tc._generate_nonce() if config.enable_nonce else None
            signed = tc._signer.sign(request.tool_id, request.data, nonce)

            # Update tool stats
            if request.tool_id in tc._tools:
                tc._tools[request.tool_id]["call_count"] += 1

            return SignResponse(
                tool_id=signed.tool_id,
                data=signed.data,
                signature=signed.signature,
                signature_id=signed.signature_id,
                timestamp=signed.timestamp,
                nonce=signed.nonce,
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/verify", response_model=VerifyResponse)
    async def verify(request: VerifyRequest) -> VerifyResponse:
        """Verify a signed response.

        Returns whether the signature is valid and the data hasn't been tampered with.
        """
        try:
            # Convert request to SignedResponse
            signed = SignedResponse(
                tool_id=request.tool_id,
                data=request.data,
                signature=request.signature,
                signature_id=request.signature_id,
                timestamp=request.timestamp,
                nonce=request.nonce,
            )

            is_valid = tc.verify(signed)
            return VerifyResponse(valid=is_valid)

        except Exception as e:
            return VerifyResponse(valid=False, error=str(e))

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        """Health check endpoint."""
        return HealthResponse(
            status="healthy",
            version="2.0.0",
            key_id=tc.get_key_id(),
            metrics_enabled=config.enable_metrics,
            nonce_backend=config.nonce_backend,
        )

    @app.get("/public-key")
    async def public_key() -> Dict[str, str]:
        """Get public key for external verification."""
        return {
            "key_id": tc.get_key_id(),
            "public_key": tc.export_public_key(),
            "algorithm": config.algorithm,
        }

    # Metrics endpoint (if prometheus available)
    if config.enable_metrics:
        try:
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

            @app.get("/metrics")
            async def metrics() -> PlainTextResponse:
                """Prometheus metrics endpoint."""
                return PlainTextResponse(
                    generate_latest(tc._metrics.registry),  # type: ignore[attr-defined]
                    media_type=CONTENT_TYPE_LATEST,
                )

        except ImportError:
            pass

    return app


# Default app instance for uvicorn
app = None


def get_app() -> "FastAPI":
    """Get or create the default FastAPI app."""
    global app
    if app is None:
        app = create_app(enable_nonce=True, enable_metrics=True, nonce_backend="memory")
    return app


# For direct uvicorn usage: uvicorn trustchain.v2.server:app
if HAS_FASTAPI:
    app = get_app()
