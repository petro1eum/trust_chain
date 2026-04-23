"""
TrustChain - Cryptographically signed AI tool responses.

"SSL for AI Agents" - Prove tool outputs are real, not hallucinated.

Author: Ed Cherednik (edcherednik@gmail.com)
Telegram: @EdCher
"""

__version__ = "3.0.0"
__author__ = "Ed Cherednik"

# KMS adapters. OSS core ships:
#   • LocalFileKeyProvider / EnvVarKeyProvider — 12-factor / baseline;
#   • VaultTransitKeyProvider — real hard-KMS (Ed25519 stays in HashiCorp Vault);
#   • AwsSecretsManagerKeyProvider — soft-KMS on AWS (seed in Secrets Manager,
#     envelope-encrypted by AWS KMS CMK).
# trustchain_pro adds CloudHSM / Azure KeyVault / PKCS#11 providers on top.
from trustchain.kms import (
    AwsSecretsManagerKeyProvider,
    EnvVarKeyProvider,
    KeyProvider,
    KeyProviderError,
    KeyProviderMetadata,
    LocalFileKeyProvider,
    VaultTransitKeyProvider,
)

# Receipt — portable, self-contained proof-of-signature object (.tcreceipt).
# Предназначен для того, чтобы «квитанцию» о подписанном ответе можно было
# передать третьей стороне (email, Slack, QR) и она проверила подпись
# локально, без обращения к production-системе.
from trustchain.receipt import (
    RECEIPT_FORMAT,
    RECEIPT_VERSION,
    Receipt,
    ReceiptError,
    ReceiptFormatError,
    ReceiptVerification,
    ReceiptVerificationError,
    build_receipt,
    verify_receipt,
)

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
    # KMS / HSM adapters (enterprise)
    "KeyProvider",
    "KeyProviderError",
    "KeyProviderMetadata",
    "LocalFileKeyProvider",
    "EnvVarKeyProvider",
    "VaultTransitKeyProvider",
    "AwsSecretsManagerKeyProvider",
    # Receipt — portable proof-of-signature (.tcreceipt)
    "Receipt",
    "ReceiptError",
    "ReceiptFormatError",
    "ReceiptVerification",
    "ReceiptVerificationError",
    "RECEIPT_FORMAT",
    "RECEIPT_VERSION",
    "build_receipt",
    "verify_receipt",
    # Exceptions
    "TrustChainError",
    "SignatureVerificationError",
    "NonceReplayError",
    "KeyNotFoundError",
]
