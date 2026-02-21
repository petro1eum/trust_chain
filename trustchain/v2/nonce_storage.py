"""Nonce storage backends for TrustChain.

Provides multiple storage options for nonce tracking:
- MemoryNonceStorage: In-memory (dev/testing, single instance)
- RedisNonceStorage: Redis-backed (production, distributed)
"""

import time
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Optional


class NonceStorage(ABC):
    """Abstract base class for nonce storage backends."""

    @abstractmethod
    def check_and_add(self, nonce: str, ttl: int = 300) -> bool:
        """Check if nonce exists, add if not.

        Args:
            nonce: The nonce string to check
            ttl: Time-to-live in seconds (for automatic expiration)

        Returns:
            True if nonce was new and added successfully
            False if nonce already exists (replay attack)
        """
        pass

    @abstractmethod
    def contains(self, nonce: str) -> bool:
        """Check if nonce exists without adding."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all stored nonces."""
        pass

    def close(self) -> None:
        """Close connections (override if needed)."""
        pass


class MemoryNonceStorage(NonceStorage):
    """In-memory nonce storage using deque.

    Best for:
    - Development and testing
    - Single-instance deployments
    - Low-volume applications

    Limitations:
    - Lost on restart
    - Doesn't work across multiple instances
    """

    def __init__(self, maxlen: int = 10000):
        """Initialize memory storage.

        Args:
            maxlen: Maximum number of nonces to store (LRU behavior)
        """
        self._nonces: deque = deque(maxlen=maxlen)
        self._nonce_set: set = set()  # O(1) lookup
        self._timestamps: dict = {}  # nonce -> expiry time

    def check_and_add(self, nonce: str, ttl: int = 300) -> bool:
        """Check and add nonce with TTL."""
        self._cleanup_expired()

        if nonce in self._nonce_set:
            return False  # Replay detected

        # Add nonce
        self._nonces.append(nonce)
        self._nonce_set.add(nonce)
        self._timestamps[nonce] = time.time() + ttl

        # Handle deque overflow (LRU eviction)
        while (
            self._nonces.maxlen is not None
            and len(self._nonce_set) > self._nonces.maxlen
        ):
            old = self._nonces.popleft()
            self._nonce_set.discard(old)
            self._timestamps.pop(old, None)

        return True

    def contains(self, nonce: str) -> bool:
        """Check if nonce exists."""
        self._cleanup_expired()
        return nonce in self._nonce_set

    def clear(self) -> None:
        """Clear all nonces."""
        self._nonces.clear()
        self._nonce_set.clear()
        self._timestamps.clear()

    def _cleanup_expired(self) -> None:
        """Remove expired nonces."""
        now = time.time()
        expired = [n for n, exp in self._timestamps.items() if exp < now]
        for nonce in expired:
            self._nonce_set.discard(nonce)
            self._timestamps.pop(nonce, None)
            # Note: deque doesn't support efficient removal, but it's bounded


class RedisNonceStorage(NonceStorage):
    """Redis-backed nonce storage for distributed systems.

    Best for:
    - Production deployments
    - Multi-instance/horizontal scaling
    - High-availability requirements

    Features:
    - Automatic TTL expiration
    - Atomic check-and-set operations
    - Tenant isolation support
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        prefix: str = "trustchain:nonce",
        tenant_id: Optional[str] = None,
    ):
        """Initialize Redis storage.

        Args:
            redis_url: Redis connection URL
            prefix: Key prefix for namespacing
            tenant_id: Optional tenant ID for multi-tenancy
        """
        try:
            import redis
        except ImportError:
            raise ImportError(
                "Redis support requires 'redis' package. "
                "Install with: pip install redis"
            )

        self._client = redis.from_url(redis_url)
        self._prefix = prefix
        self._tenant_id = tenant_id

    def _key(self, nonce: str) -> str:
        """Generate Redis key for nonce."""
        if self._tenant_id:
            return f"{self._prefix}:{self._tenant_id}:{nonce}"
        return f"{self._prefix}:{nonce}"

    def check_and_add(self, nonce: str, ttl: int = 300) -> bool:
        """Atomically check and add nonce with TTL.

        Uses Redis SETNX (SET if Not eXists) for atomic operation.
        """
        key = self._key(nonce)
        # SETNX returns True if key was set, False if already exists
        result = self._client.set(key, "1", nx=True, ex=ttl)
        return result is True

    def contains(self, nonce: str) -> bool:
        """Check if nonce exists in Redis."""
        return bool(self._client.exists(self._key(nonce)) > 0)

    def clear(self) -> None:
        """Clear all nonces for this prefix/tenant.

        Warning: Uses SCAN which may be slow on large datasets.
        """
        pattern = f"{self._prefix}:{self._tenant_id or '*'}:*"
        cursor = 0
        while True:
            cursor, keys = self._client.scan(cursor, match=pattern, count=100)
            if keys:
                self._client.delete(*keys)
            if cursor == 0:
                break

    def close(self) -> None:
        """Close Redis connection."""
        self._client.close()

    def ping(self) -> bool:
        """Check Redis connectivity."""
        try:
            return bool(self._client.ping())
        except Exception:
            return False


def create_nonce_storage(
    backend: str = "memory",
    redis_url: Optional[str] = None,
    tenant_id: Optional[str] = None,
    **kwargs: Any,
) -> NonceStorage:
    """Factory function to create nonce storage.

    Args:
        backend: "memory" or "redis"
        redis_url: Required for redis backend
        tenant_id: Optional tenant ID for multi-tenancy
        **kwargs: Additional backend-specific options

    Returns:
        NonceStorage instance
    """
    if backend == "memory":
        return MemoryNonceStorage(**kwargs)
    elif backend == "redis":
        if not redis_url:
            raise ValueError("redis_url required for redis backend")
        return RedisNonceStorage(redis_url=redis_url, tenant_id=tenant_id, **kwargs)
    else:
        raise ValueError(f"Unknown nonce storage backend: {backend}")
