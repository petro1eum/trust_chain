"""Configuration for TrustChain v2."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TrustChainConfig:
    """Main configuration for TrustChain."""

    # Crypto settings
    algorithm: str = "ed25519"

    # Cache settings
    cache_ttl: int = 3600  # 1 hour
    max_cached_responses: int = 100

    # Security settings
    enable_nonce: bool = True
    nonce_ttl: int = 300  # 5 minutes

    # Performance settings
    enable_cache: bool = True

    # Enterprise: Observability
    enable_metrics: bool = False  # Prometheus metrics (requires prometheus_client)

    # Hallucination detection patterns
    tool_claim_patterns: List[str] = field(
        default_factory=lambda: [
            r"I\s+(?:called|used|executed|ran|invoked)",
            r"I\s+(?:got|obtained|received|fetched)",
            r"API\s+(?:returned|responded|gave)",
            r"tool\s+(?:returned|gave|showed)",
            r"transaction\s+(?:id|number)",
            r"result\s+(?:is|was|shows)",
        ]
    )

    # Storage backend (for response cache)
    storage_backend: str = "memory"  # Options: memory, file, redis
    redis_url: Optional[str] = None

    # Chain persistence (Git-like .trustchain/ directory)
    enable_chain: bool = True  # Auto-record every sign() to ChainStore
    chain_storage: str = "file"  # Options: memory, file, sqlite (Pro)
    chain_dir: str = "~/.trustchain"  # Root dir for .trustchain/ structure

    # Key persistence
    key_file: Optional[str] = None  # Path to key file for persistence
    key_env_var: Optional[str] = None  # Env var name for key (base64 JSON)

    # Enterprise: Nonce storage backend
    nonce_backend: str = "memory"  # Options: memory, redis

    # Enterprise: Multi-tenancy
    tenant_id: Optional[str] = None  # Namespace for tenant isolation

    # Timestamp Authority (TSA) - RFC 3161
    tsa_url: Optional[str] = None  # e.g., "https://freetsa.org/tsr"
    tsa_enabled: bool = False  # Enable TSA timestamps for all signatures
    tsa_timeout: int = 10  # TSA request timeout in seconds

    # Certificate (identity metadata for signed responses)
    certificate: Optional[dict] = (
        None  # {"owner": "...", "organization": "...", "tier": "community|pro|enterprise"}
    )

    def __post_init__(self):
        """Validate configuration."""
        if self.algorithm not in ["ed25519", "rsa", "ecdsa"]:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        if self.cache_ttl <= 0:
            raise ValueError("cache_ttl must be positive")

        if self.max_cached_responses <= 0:
            raise ValueError("max_cached_responses must be positive")
