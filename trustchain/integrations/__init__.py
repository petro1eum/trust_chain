"""TrustChain Integrations.

Available integrations:
- FastAPI: TrustChainMiddleware, sign_response
- Flask: TrustChainFlask, sign_response (flask)
- Django: TrustChainMiddleware (django), sign_response (django)
- LangChain: to_langchain_tool, to_langchain_tools
- LangSmith: TrustChainCallbackHandler
- Pydantic v2: TrustChainModel, SignedField, SignedDict
- OpenTelemetry: TrustChainSpanProcessor, TrustChainInstrumentor
- MCP: serve_mcp, create_mcp_server
"""

# LangChain (optional)
try:
    from .langchain import (
        TrustChainLangChainTool,
        to_langchain_tool,
        to_langchain_tools,
    )
except ImportError:
    to_langchain_tool = None
    to_langchain_tools = None
    TrustChainLangChainTool = None

# LangSmith (optional)
try:
    from .langsmith import TrustChainCallbackHandler
except ImportError:
    TrustChainCallbackHandler = None

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
except ImportError:
    serve_mcp = None
    create_mcp_server = None
    TrustChainMCPServer = None

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
    # LangChain
    "to_langchain_tool",
    "to_langchain_tools",
    "TrustChainLangChainTool",
    # LangSmith
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
]
