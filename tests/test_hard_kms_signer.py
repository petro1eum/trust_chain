"""Core honors the hard-KMS contract (ADR-SEC-002 §HSM).

A hard-KMS / HSM ``KeyProvider`` keeps the private seed inside the device:
``get_seed()`` raises ``KeyProviderError``. Before this fix
``TrustChain._load_or_create_signer`` unconditionally called ``get_seed()`` to
build an in-process key, so hard-KMS providers (Vault Transit, PKCS#11) could
not sign the ledger at all. Now the core builds a *delegating* signer that
routes every signature through ``provider.sign()`` and never touches the seed.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain.kms import KeyProvider, KeyProviderError, KeyProviderMetadata
from trustchain.v2.core import TrustChain, TrustChainConfig
from trustchain.v2.signer import Signer


class _FakeHardKMS:
    """Hard-KMS provider: seed stays 'in the device'; get_seed() raises."""

    def __init__(self) -> None:
        self._priv = ed25519.Ed25519PrivateKey.generate()
        self._pub_raw = self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.seed_access_attempts = 0

    def get_metadata(self) -> KeyProviderMetadata:
        return KeyProviderMetadata(
            provider="fake-hsm", key_id="fake-hsm-1", algorithm="ed25519"
        )

    def get_public_key(self) -> bytes:
        return self._pub_raw

    def get_key_id(self) -> str:
        return "fake-hsm-1"

    def get_seed(self) -> bytes:
        self.seed_access_attempts += 1
        raise KeyProviderError("fake-hsm: seed never leaves the device")

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._priv.public_key().verify(signature, data)
            return True
        except Exception:
            return False


def _config(provider):
    return TrustChainConfig(
        key_provider=provider,
        enable_chain=False,
        enable_nonce=False,
        enable_cache=False,
        enable_pki=False,
    )


def test_fake_provider_satisfies_protocol():
    assert isinstance(_FakeHardKMS(), KeyProvider)


def test_core_builds_delegating_signer_for_hard_kms():
    provider = _FakeHardKMS()
    tc = TrustChain(_config(provider))

    signer = tc._signer
    assert isinstance(signer, Signer)
    # Hard-KMS: no in-process private key; provider wired for delegation.
    assert signer._private_key is None
    assert signer._provider is provider
    assert signer.key_id == "fake-hsm-1"


def test_hard_kms_signer_signs_and_verifies():
    provider = _FakeHardKMS()
    signer = TrustChain(_config(provider))._signer

    resp = signer.sign("tool.test", {"x": 1})
    assert signer.verify(resp) is True

    # Signature actually verifies against the provider's public key.
    pub = ed25519.Ed25519PublicKey.from_public_bytes(provider.get_public_key())
    import json

    from trustchain.v2.signer import _build_canonical_data

    canonical = _build_canonical_data(
        tool_id=resp.tool_id,
        data=resp.data,
        timestamp=resp.timestamp,
        nonce=resp.nonce,
        parent_signature=resp.parent_signature,
        parent_signatures=resp.parent_signatures,
        metadata=resp.metadata,
        certificate=resp.certificate,
        tsa_proof=resp.tsa_proof,
    )
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    pub.verify(base64.b64decode(resp.signature), payload)  # raises on mismatch


def test_hard_kms_signer_never_extracts_seed():
    provider = _FakeHardKMS()
    signer = TrustChain(_config(provider))._signer
    # get_seed() is attempted exactly once (the probe) and never for signing.
    assert provider.seed_access_attempts == 1
    signer.sign("tool.test", {"a": 2})
    assert provider.seed_access_attempts == 1


def test_hard_kms_signer_cannot_export_keys():
    provider = _FakeHardKMS()
    signer = TrustChain(_config(provider))._signer
    with pytest.raises(ValueError, match="hard-KMS"):
        signer.export_keys()


def test_get_public_key_matches_provider():
    provider = _FakeHardKMS()
    signer = TrustChain(_config(provider))._signer
    assert base64.b64decode(signer.get_public_key()) == provider.get_public_key()
