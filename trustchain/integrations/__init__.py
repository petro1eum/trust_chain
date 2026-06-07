"""TrustChain Integrations.

Optional framework adapters. LangChain / LangSmith are lazy-loaded so
``import trustchain`` does not pull langchain_core (important on Python 3.14+).

Available integrations:
- FastAPI: TrustChainMiddleware, sign_response
- Flask: TrustChainFlask, sign_response (flask)
- Django: TrustChainMiddleware (django), sign_response (django)
- LangChain: to_langchain_tool, to_langchain_tools (lazy)
- LangSmith: TrustChainCallbackHandler (lazy)
- Pydantic v2: TrustChainModel, SignedField, SignedDict
- OpenTelemetry: TrustChainSpanProcessor, TrustChainInstrumentor
- MCP: serve_mcp, create_mcp_server
"""

from __future__ import annotations

import importlib
from typing import Any

# LangChain / LangSmith — lazy (see __getattr__); avoids langchain_core on import trustchain
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "to_langchain_tool": (".langchain", "to_langchain_tool"),
    "to_langchain_tools": (".langchain", "to_langchain_tools"),
    "TrustChainLangChainTool": (".langchain", "TrustChainLangChainTool"),
    "TrustChainCallbackHandler": (".langsmith", "TrustChainCallbackHandler"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        module, attr = _LAZY_EXPORTS[name]
        try:
            mod = importlib.import_module(module, __name__)
            value = getattr(mod, attr)
        except ImportError:
            value = None
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_EXPORTS.keys()) + list(__all__))


# Pydantic v2 (optional)
try:
    from .pydantic_v2 import SignedDict, SignedField, TrustChainModel
except ImportError:
    TrustChainModel = None
    SignedField = None
    SignedDict = None

# OpenTelemetry (optional)
try:
    from .opentelemetry import (
        ATTR_TRUSTCHAIN_CHAIN_ID,
        ATTR_TRUSTCHAIN_NONCE,
        ATTR_TRUSTCHAIN_PARENT_SIGNATURE,
        ATTR_TRUSTCHAIN_SIGNATURE,
        ATTR_TRUSTCHAIN_SIGNATURE_ID,
        ATTR_TRUSTCHAIN_TIMESTAMP,
        ATTR_TRUSTCHAIN_TOOL_ID,
        ATTR_TRUSTCHAIN_VERIFIED,
        TrustChainInstrumentor,
        TrustChainSpanProcessor,
        create_traced_trustchain,
        instrument_span,
        set_trustchain_span_attributes,
    )
except ImportError:
    TrustChainSpanProcessor = None
    TrustChainInstrumentor = None
    instrument_span = None
    create_traced_trustchain = None
    set_trustchain_span_attributes = None
    ATTR_TRUSTCHAIN_TOOL_ID = None
    ATTR_TRUSTCHAIN_SIGNATURE = None
    ATTR_TRUSTCHAIN_SIGNATURE_ID = None
    ATTR_TRUSTCHAIN_VERIFIED = None
    ATTR_TRUSTCHAIN_TIMESTAMP = None
    ATTR_TRUSTCHAIN_NONCE = None
    ATTR_TRUSTCHAIN_PARENT_SIGNATURE = None
    ATTR_TRUSTCHAIN_CHAIN_ID = None

# MCP (optional)
try:
    from .mcp import TrustChainMCPServer, create_mcp_server, serve_mcp
    from .mcp_proxy import run_proxy
except ImportError:
    serve_mcp = None
    create_mcp_server = None
    TrustChainMCPServer = None
    run_proxy = None

# OnaiDocs bridge (optional)
try:
    from .onaidocs import OnaiDocsTrustClient
except ImportError:
    OnaiDocsTrustClient = None

# FastAPI (optional)
try:
    from .fastapi import TrustChainAPIRouter, TrustChainMiddleware, sign_response
except ImportError:
    TrustChainMiddleware = None
    sign_response = None
    TrustChainAPIRouter = None

# Flask (optional)
try:
    from .flask import TrustChainFlask, get_public_key_endpoint
    from .flask import sign_response as flask_sign_response
except ImportError:
    TrustChainFlask = None
    flask_sign_response = None
    get_public_key_endpoint = None

# Django (optional)
try:
    from .django import TrustChainMiddleware as DjangoTrustChainMiddleware
    from .django import get_public_key_view, sign_drf_response
    from .django import sign_response as django_sign_response
except ImportError:
    DjangoTrustChainMiddleware = None
    django_sign_response = None
    get_public_key_view = None
    sign_drf_response = None

__all__ = [
    # FastAPI
    "TrustChainMiddleware",
    "sign_response",
    "TrustChainAPIRouter",
    # Flask
    "TrustChainFlask",
    "flask_sign_response",
    "get_public_key_endpoint",
    # Django
    "DjangoTrustChainMiddleware",
    "django_sign_response",
    "get_public_key_view",
    "sign_drf_response",
    # LangChain (lazy)
    "to_langchain_tool",
    "to_langchain_tools",
    "TrustChainLangChainTool",
    # LangSmith (lazy)
    "TrustChainCallbackHandler",
    # Pydantic v2
    "TrustChainModel",
    "SignedField",
    "SignedDict",
    # OpenTelemetry
    "TrustChainSpanProcessor",
    "TrustChainInstrumentor",
    "instrument_span",
    "create_traced_trustchain",
    "set_trustchain_span_attributes",
    "ATTR_TRUSTCHAIN_TOOL_ID",
    "ATTR_TRUSTCHAIN_SIGNATURE",
    "ATTR_TRUSTCHAIN_SIGNATURE_ID",
    "ATTR_TRUSTCHAIN_VERIFIED",
    "ATTR_TRUSTCHAIN_TIMESTAMP",
    "ATTR_TRUSTCHAIN_NONCE",
    "ATTR_TRUSTCHAIN_PARENT_SIGNATURE",
    "ATTR_TRUSTCHAIN_CHAIN_ID",
    # MCP
    "serve_mcp",
    "create_mcp_server",
    "TrustChainMCPServer",
    "run_proxy",
    # OnaiDocs
    "OnaiDocsTrustClient",
]
