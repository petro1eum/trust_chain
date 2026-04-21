"""Configuration for TrustChain v2."""

import os
import warnings
from dataclasses import dataclass, field
from typing import Any, List, Optional


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
    # chain_storage:
    #   "postgres"   — PostgreSQL-backed VerifiableChainStore (v3 default, ADR-SEC-002)
    #   "verifiable" — legacy file-backed CT log (chain.log + SQLite index),
    #                  deprecated and will be removed in a future release
    #   "file"       — legacy one-file-per-op JSON storage
    #   "memory"     — ephemeral, tests only
    chain_storage: str = "postgres"
    chain_dir: str = "~/.trustchain"  # Root dir for legacy file-backed chain
    # PostgreSQL DSN for the verifiable log; if empty the env var
    # $TC_VERIFIABLE_LOG_DSN is used (fail-closed if neither is set).
    chain_dsn: Optional[str] = None
    # PostgreSQL schema for the verifiable log (ADR-SEC-002 isolation contract).
    chain_schema: str = "tc_verifiable_log"

    # Key persistence
    key_file: Optional[str] = None  # Path to key file for persistence
    key_env_var: Optional[str] = None  # Env var name for key (base64 JSON)

    # Enterprise: Nonce storage backend
    nonce_backend: str = "memory"  # Options: memory, redis
    nonce_storage: Optional[Any] = None  # Explicit nonce storage adapter/backend

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

    # X.509 PKI for AI Agents
    enable_pki: bool = True  # Auto-bootstrap Root CA + issue agent cert
    pki_agent_id: str = ""  # Agent CN (auto-generated if empty)
    pki_validity_hours: int = 1  # Short-lived agent cert validity
    pki_organization: str = "TrustChain"  # X.509 Organization name

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.algorithm != "ed25519":
            raise ValueError(
                "TrustChain v2 supports only algorithm='ed25519' (RSA/ECDSA removed from v2 surface).",
            )

        if self.cache_ttl <= 0:
            raise ValueError("cache_ttl must be positive")

        if self.max_cached_responses <= 0:
            raise ValueError("max_cached_responses must be positive")

        if self.nonce_ttl <= 0:
            raise ValueError("nonce_ttl must be positive")

        # ADR-SEC-002 / ADR-SEC-005:
        # v3 default — chain_storage='postgres'.  Однако в dev/tests
        # поднимать PG ради каждого `TrustChain()` неоправданно, поэтому если
        # ни `chain_dsn`, ни `TC_VERIFIABLE_LOG_DSN` не выставлены —
        # автоматически переключаемся на in-memory backend с предупреждением.
        # В production DSN гарантируется docker-compose / Helm, и fallback не
        # активируется.  Явно выставленный `TC_STRICT_CHAIN=1` превращает
        # отсутствие DSN в hard-error (для runtime-самопроверок).
        if self.enable_chain and self.chain_storage == "postgres":
            has_dsn = bool(self.chain_dsn or os.environ.get("TC_VERIFIABLE_LOG_DSN"))
            if not has_dsn:
                if os.environ.get("TC_STRICT_CHAIN", "").lower() in ("1", "true", "yes"):
                    raise RuntimeError(
                        "chain_storage='postgres' requires TC_VERIFIABLE_LOG_DSN "
                        "(TC_STRICT_CHAIN=1).  Set the DSN or pass "
                        "chain_storage='memory' explicitly."
                    )
                warnings.warn(
                    "chain_storage='postgres' запрошен, но TC_VERIFIABLE_LOG_DSN "
                    "не задан — автоматически используется in-memory backend. "
                    "В production выставьте DSN (ADR-SEC-005) или TC_STRICT_CHAIN=1 "
                    "для fail-closed поведения.",
                    RuntimeWarning,
                    stacklevel=3,
                )
                self.chain_storage = "memory"
