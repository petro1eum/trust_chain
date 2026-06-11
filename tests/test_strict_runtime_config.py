"""Fail-closed runtime config: TC_STRICT_CHAIN / TC_STRICT_NONCE."""

from __future__ import annotations

import os

import pytest

from trustchain.v2.config import TrustChainConfig


def test_strict_chain_requires_dsn(monkeypatch):
    monkeypatch.setenv("TC_STRICT_CHAIN", "1")
    monkeypatch.delenv("TC_VERIFIABLE_LOG_DSN", raising=False)
    with pytest.raises(RuntimeError, match="TC_VERIFIABLE_LOG_DSN"):
        TrustChainConfig(chain_storage="postgres", enable_chain=True)


def test_strict_chain_allows_explicit_memory(monkeypatch):
    monkeypatch.setenv("TC_STRICT_CHAIN", "1")
    monkeypatch.delenv("TC_VERIFIABLE_LOG_DSN", raising=False)
    cfg = TrustChainConfig(chain_storage="memory", enable_chain=True)
    assert cfg.chain_storage == "memory"


def test_strict_nonce_rejects_memory_backend(monkeypatch):
    monkeypatch.setenv("TC_STRICT_NONCE", "1")
    with pytest.raises(RuntimeError, match="nonce_backend='memory'"):
        TrustChainConfig(enable_nonce=True, nonce_backend="memory")


def test_production_memory_nonce_warns(monkeypatch):
    monkeypatch.setenv("TC_ENVIRONMENT", "production")
    monkeypatch.delenv("TC_STRICT_NONCE", raising=False)
    with pytest.warns(RuntimeWarning, match="nonce_backend='memory'"):
        TrustChainConfig(enable_nonce=True, nonce_backend="memory")
