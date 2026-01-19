"""Prometheus metrics for TrustChain (optional).

Usage:
    tc = TrustChain(TrustChainConfig(enable_metrics=True))

    # Get metrics for /metrics endpoint
    from prometheus_client import generate_latest
    print(generate_latest())
"""

import time
from contextlib import contextmanager
from typing import Optional

try:
    from prometheus_client import Counter, Histogram

    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False


class TrustChainMetrics:
    """Prometheus metrics. Does nothing if prometheus_client not installed."""

    def __init__(self, enabled: bool = True, prefix: str = "trustchain"):
        """Initialize metrics with optional prefix."""
        self.enabled = enabled and HAS_PROMETHEUS
        if not self.enabled:
            return

        self.signs_total = Counter(
            f"{prefix}_signs_total", "Sign operations", ["tool_id", "status"]
        )
        self.sign_latency = Histogram(
            f"{prefix}_sign_seconds", "Sign latency", ["tool_id"]
        )
        self.verifies_total = Counter(
            f"{prefix}_verifies_total", "Verify operations", ["status"]
        )
        self.nonce_rejects = Counter(
            f"{prefix}_nonce_rejects_total", "Replay attacks blocked"
        )

    @contextmanager
    def track_sign(self, tool_id: str):
        """Track sign operation latency and success/error count."""
        if not self.enabled:
            yield
            return
        start = time.perf_counter()
        try:
            yield
            self.signs_total.labels(tool_id=tool_id, status="ok").inc()
        except Exception:
            self.signs_total.labels(tool_id=tool_id, status="error").inc()
            raise
        finally:
            self.sign_latency.labels(tool_id=tool_id).observe(
                time.perf_counter() - start
            )

    @contextmanager
    def track_verify(self):
        """Track verify operation count."""
        if not self.enabled:
            yield
            return
        try:
            yield
            self.verifies_total.labels(status="ok").inc()
        except Exception:
            self.verifies_total.labels(status="error").inc()
            raise

    def record_nonce_reject(self):
        """Record a nonce rejection (blocked replay attack)."""
        if self.enabled:
            self.nonce_rejects.inc()


# Singleton
_metrics: Optional[TrustChainMetrics] = None


def get_metrics(enabled: bool = True) -> TrustChainMetrics:
    """Get or create metrics instance."""
    global _metrics
    if _metrics is None:
        _metrics = TrustChainMetrics(enabled=enabled)
    return _metrics
