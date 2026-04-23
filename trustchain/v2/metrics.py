"""Prometheus metrics for TrustChain (optional).

Usage:
    tc = TrustChain(TrustChainConfig(enable_metrics=True))

    # Get metrics for /metrics endpoint
    from prometheus_client import generate_latest
    print(generate_latest())
"""

import time
from contextlib import contextmanager
from typing import Any, Optional

try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False
    CollectorRegistry = None  # type: ignore[assignment,misc]


class TrustChainMetrics:
    """Prometheus metrics contract (enterprise observability).

    Exports a stable set of metric names for dashboards/alerts:

    * ``trustchain_signs_total{tool_id,status}`` — counter of sign operations
    * ``trustchain_sign_seconds{tool_id}`` — histogram of sign latency
    * ``trustchain_verifies_total{status}`` — counter of verify calls
    * ``trustchain_nonce_rejects_total`` — blocked replays
    * ``trustchain_chain_length`` — gauge of verifiable log length
    * ``trustchain_chain_appends_total{status}`` — append-to-chain counter
    * ``trustchain_chain_append_seconds`` — histogram of append latency
    * ``trustchain_pkix_verify_fail_total{reason}`` — PKIX/CRL failures

    Silent no-op when ``prometheus_client`` is not installed.
    """

    def __init__(
        self,
        enabled: bool = True,
        prefix: str = "trustchain",
        registry: Optional["CollectorRegistry"] = None,
    ):
        """Initialize metrics with optional prefix / custom registry.

        ``registry`` — опциональный ``CollectorRegistry``. Нужен в тестах и
        в multi-tenant-сценариях, чтобы избежать «Duplicated timeseries»
        при повторной инициализации в том же процессе.
        """
        self.enabled = enabled and HAS_PROMETHEUS
        if not self.enabled:
            return

        reg_kw = {"registry": registry} if registry is not None else {}

        self.signs_total = Counter(
            f"{prefix}_signs_total",
            "Sign operations",
            ["tool_id", "status"],
            **reg_kw,
        )
        self.sign_latency = Histogram(
            f"{prefix}_sign_seconds", "Sign latency", ["tool_id"], **reg_kw
        )
        self.verifies_total = Counter(
            f"{prefix}_verifies_total", "Verify operations", ["status"], **reg_kw
        )
        self.nonce_rejects = Counter(
            f"{prefix}_nonce_rejects_total", "Replay attacks blocked", **reg_kw
        )
        # Chain-level (ADR-SEC-005 observability contract).
        self.chain_length = Gauge(
            f"{prefix}_chain_length",
            "Current length of the verifiable log (Merkle leaves count)",
            **reg_kw,
        )
        self.chain_appends_total = Counter(
            f"{prefix}_chain_appends_total",
            "Chain append operations",
            ["status"],
            **reg_kw,
        )
        self.chain_append_seconds = Histogram(
            f"{prefix}_chain_append_seconds",
            "Latency of chain append (sign + DB insert + tree update)",
            **reg_kw,
        )
        self.pkix_verify_fail_total = Counter(
            f"{prefix}_pkix_verify_fail_total",
            "PKIX / CRL verification failures by reason",
            ["reason"],
            **reg_kw,
        )

    @contextmanager
    def track_sign(self, tool_id: str) -> Any:
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
    def track_verify(self) -> Any:
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

    def record_nonce_reject(self) -> None:
        """Record a nonce rejection (blocked replay attack)."""
        if self.enabled:
            self.nonce_rejects.inc()

    # ── Chain-level helpers ──────────────────────────────────────────────

    def set_chain_length(self, length: int) -> None:
        """Publish current Merkle-log length (call after ``append`` / reload)."""
        if self.enabled:
            self.chain_length.set(length)

    @contextmanager
    def track_chain_append(self) -> Any:
        """Context manager wrapping a single chain-append call."""
        if not self.enabled:
            yield
            return
        start = time.perf_counter()
        try:
            yield
            self.chain_appends_total.labels(status="ok").inc()
        except Exception:
            self.chain_appends_total.labels(status="error").inc()
            raise
        finally:
            self.chain_append_seconds.observe(time.perf_counter() - start)

    def record_pkix_failure(self, reason: str) -> None:
        """Record a PKIX/CRL failure with a stable ``reason`` label.

        ``reason`` should be one of the ``tc-verify --strict`` exit-code
        categories (e.g. ``"signature_bad"``, ``"cert_revoked"``,
        ``"issuer_mismatch"``) so dashboards can filter by failure class.
        """
        if self.enabled:
            self.pkix_verify_fail_total.labels(reason=reason).inc()


# Singleton
_metrics: Optional[TrustChainMetrics] = None


def get_metrics(enabled: bool = True) -> TrustChainMetrics:
    """Get or create metrics instance."""
    global _metrics
    if _metrics is None:
        _metrics = TrustChainMetrics(enabled=enabled)
    return _metrics
