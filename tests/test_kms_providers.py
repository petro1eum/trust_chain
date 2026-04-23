"""Tests for trustchain.kms (pluggable KeyProvider — enterprise contract)."""

from __future__ import annotations

import base64
import json
import os

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.kms import (
    EnvVarKeyProvider,
    KeyProvider,
    KeyProviderError,
    LocalFileKeyProvider,
)


def test_local_file_provider_roundtrip(tmp_path):
    path = tmp_path / "keys.json"
    p1 = LocalFileKeyProvider(path)
    # Reload from the same file — must yield same key_id/pubkey.
    p2 = LocalFileKeyProvider(path)
    assert p1.get_key_id() == p2.get_key_id()
    assert p1.get_public_key() == p2.get_public_key()
    assert p1.get_seed() == p2.get_seed()
    # Metadata is logged-safe.
    md = p1.get_metadata()
    assert md.provider == "local-file"
    assert md.algorithm == "ed25519"
    assert str(path) in (md.uri or "")


def test_local_file_provider_no_autocreate(tmp_path):
    missing = tmp_path / "absent.json"
    with pytest.raises(KeyProviderError):
        LocalFileKeyProvider(missing, auto_create=False)


def test_local_file_provider_sign_verify(tmp_path):
    p = LocalFileKeyProvider(tmp_path / "k.json")
    msg = b"hello-kms"
    sig = p.sign(msg)
    assert p.verify(msg, sig) is True
    assert p.verify(b"tampered", sig) is False


def test_env_var_provider_roundtrip(tmp_path, monkeypatch):
    # Prepare an env-encoded key by round-tripping through LocalFileKeyProvider.
    p_file = LocalFileKeyProvider(tmp_path / "k.json")
    payload = {
        "type": "ed25519",
        "key_id": p_file.get_key_id(),
        "private_key": base64.b64encode(p_file.get_seed()).decode("ascii"),
        "algorithm": "ed25519",
    }
    env_val = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    monkeypatch.setenv("TC_TEST_PRIVKEY", env_val)

    p_env = EnvVarKeyProvider("TC_TEST_PRIVKEY")
    assert p_env.get_key_id() == p_file.get_key_id()
    assert p_env.get_public_key() == p_file.get_public_key()

    msg = b"x"
    sig = p_env.sign(msg)
    assert p_env.verify(msg, sig) is True
    assert p_file.verify(msg, sig) is True


def test_env_var_provider_missing(monkeypatch):
    monkeypatch.delenv("TC_TEST_MISSING", raising=False)
    with pytest.raises(KeyProviderError):
        EnvVarKeyProvider("TC_TEST_MISSING")


def test_env_var_provider_invalid_value(monkeypatch):
    monkeypatch.setenv("TC_TEST_BROKEN", "not-base64-json")
    with pytest.raises(KeyProviderError):
        EnvVarKeyProvider("TC_TEST_BROKEN")


def test_trustchain_accepts_key_provider(tmp_path):
    # File-backed provider wired into TrustChainConfig.key_provider
    p = LocalFileKeyProvider(tmp_path / "k.json")
    tc = TrustChain(
        TrustChainConfig(
            key_provider=p,
            enable_chain=False,
            enable_pki=False,
            chain_storage="memory",
        )
    )
    # Same public key must be used by the Signer
    assert tc._signer.get_public_key() == base64.b64encode(p.get_public_key()).decode(
        "ascii"
    )


def test_protocol_runtime_checkable(tmp_path):
    p = LocalFileKeyProvider(tmp_path / "k.json")
    assert isinstance(p, KeyProvider)
