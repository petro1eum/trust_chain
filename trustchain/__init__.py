"""
TrustChain - Cryptographically signed AI tool responses.

"SSL for AI Agents" - Prove tool outputs are real, not hallucinated.

Author: Ed Cherednik (edcherednik@gmail.com)
Telegram: @EdCher
"""

__version__ = "2.3.1"
__author__ = "Ed Cherednik"

# Core exports
from trustchain.utils.exceptions import (
    KeyNotFoundError,
    NonceReplayError,
    SignatureVerificationError,
    TrustChainError,
)
from trustchain.v2 import (
    AsyncTrustChain,
    AsyncTrustChainSession,
    RedisNonceStorage,
    SignedResponse,
    TenantInfo,
    TenantManager,
    TrustChain,
    TrustChainConfig,
    TrustChainVerifier,
    VerificationResult,
    create_trustchain,
    get_logger,
    get_metrics,
    setup_logging,
)

# Policy hooks (OSS) - for full PolicyEngine see TrustChain Pro
from trustchain.v2.policy_hooks import (
    PolicyHook,
    PolicyHookRegistry,
    get_policy_registry,
    register_policy_hook,
)

# Reasoning (basic version - OSS)
from trustchain.v2.reasoning import ReasoningChain

try:
    from trustchain.integrations.onaidocs import OnaiDocsTrustClient
except Exception:  # optional integration
    OnaiDocsTrustClient = None  # type: ignore

__all__ = [
    # Core - Cryptographic signing
    "TrustChain",
    "AsyncTrustChain",
    "AsyncTrustChainSession",
    "TrustChainConfig",
    "SignedResponse",
    "TrustChainVerifier",
    "VerificationResult",
    # Chain of Trust
    "ReasoningChain",
    "OnaiDocsTrustClient",
    # Policy hooks (extensibility)
    "PolicyHook",
    "PolicyHookRegistry",
    "register_policy_hook",
    "get_policy_registry",
    # Multi-tenancy
    "TenantManager",
    "TenantInfo",
    # Observability
    "get_metrics",
    "setup_logging",
    "get_logger",
    # Storage
    "RedisNonceStorage",
    "create_trustchain",
    # Exceptions
    "TrustChainError",
    "SignatureVerificationError",
    "NonceReplayError",
    "KeyNotFoundError",
]
