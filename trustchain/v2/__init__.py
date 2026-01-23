"""
TrustChain v2 - Cryptographically signed AI tool responses.

Enterprise-ready: Redis, Prometheus, multi-tenancy, REST API, TSA.
"""

from .config import TrustChainConfig
from .core import TrustChain
from .logging import get_logger, setup_logging
from .metrics import TrustChainMetrics, get_metrics
from .nonce_storage import MemoryNonceStorage, NonceStorage, RedisNonceStorage
from .session import TrustChainSession, create_session
from .signer import SignedResponse
from .storage import MemoryStorage, Storage
from .tenants import TenantInfo, TenantManager
from .tsa import TSAClient, TSAError, TSAResponse, TSAVerifyResult, get_tsa_client
from .verifier import TrustChainVerifier, VerificationResult

__version__ = "2.3.0"

__all__ = [
    # Core
    "TrustChain",
    "TrustChainConfig",
    "SignedResponse",
    "TrustChainVerifier",
    "VerificationResult",
    # Session
    "TrustChainSession",
    "create_session",
    # TSA (Timestamp Authority)
    "TSAClient",
    "TSAResponse",
    "TSAVerifyResult",
    "TSAError",
    "get_tsa_client",
    # Enterprise
    "TenantManager",
    "TenantInfo",
    "get_metrics",
    "setup_logging",
    "get_logger",
    "RedisNonceStorage",
]


def create_trustchain(**kwargs) -> TrustChain:
    """Create TrustChain with custom config."""
    return TrustChain(TrustChainConfig(**kwargs))
