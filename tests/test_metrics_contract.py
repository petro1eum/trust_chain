"""Enterprise metrics contract (ADR-SEC-005 Observability).

Смысл: дашборды и алерты ссылаются на стабильные имена метрик. Мы хотим,
чтобы CI падал, если кто-то случайно переименовал/удалил метрику из
контракта. Никаких изменений без явного обновления этого теста.
"""

from __future__ import annotations

import pytest

pytest.importorskip("prometheus_client")

from prometheus_client import CollectorRegistry, generate_latest  # noqa: E402

from trustchain.v2.metrics import TrustChainMetrics  # noqa: E402

CONTRACT_METRICS = {
    "trustchain_signs_total",
    "trustchain_sign_seconds",
    "trustchain_verifies_total",
    "trustchain_nonce_rejects_total",
    "trustchain_chain_length",
    "trustchain_chain_appends_total",
    "trustchain_chain_append_seconds",
    "trustchain_pkix_verify_fail_total",
}


@pytest.fixture
def metrics() -> TrustChainMetrics:
    """Isolated registry per test — иначе ``Duplicated timeseries``."""
    return TrustChainMetrics(enabled=True, registry=CollectorRegistry())


def _expose_names(m: TrustChainMetrics, reg: CollectorRegistry) -> set[str]:
    with m.track_sign("t"):
        pass
    with m.track_verify():
        pass
    with m.track_chain_append():
        pass
    m.set_chain_length(0)
    m.record_nonce_reject()
    m.record_pkix_failure("signature_bad")
    raw = generate_latest(reg).decode()
    names = set()
    for line in raw.splitlines():
        if line.startswith("# HELP ") or line.startswith("# TYPE "):
            parts = line.split()
            if len(parts) >= 3:
                names.add(parts[2])
    return names


def test_all_contract_metrics_registered():
    reg = CollectorRegistry()
    m = TrustChainMetrics(enabled=True, registry=reg)
    assert m.enabled
    names = _expose_names(m, reg)
    missing = CONTRACT_METRICS - names
    assert not missing, f"Нарушение observability-контракта: отсутствуют {missing}"


def test_chain_length_gauge_updates():
    reg = CollectorRegistry()
    m = TrustChainMetrics(enabled=True, registry=reg)
    m.set_chain_length(42)
    raw = generate_latest(reg).decode()
    assert "trustchain_chain_length 42.0" in raw


def test_pkix_failure_labeled_by_reason():
    reg = CollectorRegistry()
    m = TrustChainMetrics(enabled=True, registry=reg)
    m.record_pkix_failure("cert_revoked")
    m.record_pkix_failure("cert_revoked")
    m.record_pkix_failure("issuer_mismatch")
    raw = generate_latest(reg).decode()
    assert 'trustchain_pkix_verify_fail_total{reason="cert_revoked"} 2.0' in raw
    assert 'trustchain_pkix_verify_fail_total{reason="issuer_mismatch"} 1.0' in raw


def test_disabled_metrics_are_noop():
    m = TrustChainMetrics(enabled=False)
    with m.track_chain_append():
        pass
    m.set_chain_length(100)
    m.record_pkix_failure("whatever")
