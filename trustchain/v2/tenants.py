"""Multi-tenancy for TrustChain.

Usage:
    from trustchain.v2.tenants import TenantManager

    manager = TenantManager(redis_url="redis://localhost:6379")
    tc = manager.get_or_create("customer_123")
"""

import os
import time
from dataclasses import dataclass
from typing import Dict, Optional

from .config import TrustChainConfig
from .core import TrustChain


@dataclass
class TenantInfo:
    """Tenant metadata."""

    tenant_id: str
    key_id: str
    created_at: float


class TenantManager:
    """Manages TrustChain instances per tenant with isolated keys."""

    def __init__(
        self,
        base_config: Optional[TrustChainConfig] = None,
        key_storage_dir: Optional[str] = None,
        redis_url: Optional[str] = None,
    ):
        """Initialize manager with optional config, key storage, and Redis URL."""
        self._base_config = base_config or TrustChainConfig()
        self._key_storage_dir = key_storage_dir
        self._redis_url = redis_url
        self._tenants: Dict[str, TrustChain] = {}
        self._info: Dict[str, TenantInfo] = {}

        if key_storage_dir:
            os.makedirs(key_storage_dir, exist_ok=True)

    def get_or_create(self, tenant_id: str) -> TrustChain:
        """Get existing tenant or create new one with isolated keys."""
        if tenant_id in self._tenants:
            return self._tenants[tenant_id]

        key_file = None
        if self._key_storage_dir:
            key_file = os.path.join(self._key_storage_dir, f"{tenant_id}_keys.json")

        config = TrustChainConfig(
            algorithm=self._base_config.algorithm,
            enable_nonce=self._base_config.enable_nonce,
            enable_metrics=self._base_config.enable_metrics,
            redis_url=self._redis_url,
            key_file=key_file,
            nonce_backend="redis" if self._redis_url else "memory",
            tenant_id=tenant_id,
        )

        tc = TrustChain(config)

        if key_file:
            tc.save_keys()

        self._tenants[tenant_id] = tc
        self._info[tenant_id] = TenantInfo(
            tenant_id=tenant_id,
            key_id=tc.get_key_id(),
            created_at=time.time(),
        )

        return tc

    def get(self, tenant_id: str) -> Optional[TrustChain]:
        """Get tenant by ID."""
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> Dict[str, TenantInfo]:
        """List all tenants."""
        return self._info.copy()

    @property
    def count(self) -> int:
        """Return number of active tenants."""
        return len(self._tenants)
