"""
TrustChain - Cryptographically signed AI tool responses.

Author: Ed Cherednik (edcherednik@gmail.com)
Telegram: @EdCher
"""

__version__ = "2.1.0"
__author__ = "Ed Cherednik"

# Re-export everything from v2
# Exceptions
from trustchain.utils.exceptions import (
    KeyNotFoundError,
    NonceReplayError,
    SignatureVerificationError,
    TrustChainError,
)
from trustchain.v2 import (
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
from trustchain.v2.graph import ExecutionGraph
from trustchain.v2.policy import PolicyEngine, PolicyViolationError

__all__ = [
    # Core
    "TrustChain",
    "TrustChainConfig",
    "SignedResponse",
    "TrustChainVerifier",
    "VerificationResult",
    # Enterprise
    "TenantManager",
    "TenantInfo",
    "get_metrics",
    "setup_logging",
    "get_logger",
    "RedisNonceStorage",
    "create_trustchain",
    # Governance (Phase 13-14)
    "PolicyEngine",
    "PolicyViolationError",
    "ExecutionGraph",
    # Exceptions
    "TrustChainError",
    "SignatureVerificationError",
    "NonceReplayError",
    "KeyNotFoundError",
]
