"""PRO-KMS-1 regression: VaultTransitKeyProvider.sign() round-trips with verify().

The audit found that ``sign()`` asked Vault Transit to pre-hash (sha2-256) and
ASN.1-marshal the Ed25519 signature, producing a ~72-byte DER blob that the
provider's own *raw* Ed25519 ``verify()`` rejects. The fix requests
``hash_algorithm="none"`` + ``marshaling_algorithm="jws"`` (raw) and guards that
the decoded signature is exactly 64 bytes.

These tests are DB-free and require neither a live Vault nor the ``hvac`` /
``moto`` packages: we inject a faithful fake ``hvac`` module into
``sys.modules`` whose ``sign_data`` *honours the marshaling/hash kwargs it is
given* — returning a raw 64-byte signature only when called the correct way and
an ASN.1-wrapped signature otherwise (exactly how real Vault Transit behaves).
This makes the round-trip assertion FAIL on the old code (asn1/sha2-256) and
PASS on the fixed code (jws/none).
"""

from __future__ import annotations

import base64
import sys
import types

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def _raw_pub(priv: ed25519.Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _install_fake_hvac(monkeypatch, priv, *, override_payload=None):
    """Inject a Vault-Transit-faithful fake ``hvac`` module.

    ``sign_data`` inspects the kwargs the provider passes:
      * jws + none  -> raw 64-byte Ed25519 signature (what real Vault returns)
      * anything else (e.g. asn1 + sha2-256) -> DER/ASN.1-wrapped signature
        that raw Ed25519 verification cannot accept.
    If ``override_payload`` is given, it is returned verbatim (used to simulate
    a short/malformed signature regardless of marshaling).
    """
    pub_raw = _raw_pub(priv)

    class _FakeTransit:
        def __init__(self):
            self.last_kwargs = None

        def read_key(self, name, mount_point):
            return {
                "data": {
                    "type": "ed25519",
                    "latest_version": 1,
                    "min_decryption_version": 1,
                    "keys": {
                        "1": {"public_key": base64.b64encode(pub_raw).decode("ascii")},
                    },
                }
            }

        def sign_data(
            self,
            name,
            hash_input,
            mount_point,
            hash_algorithm,
            marshaling_algorithm,
        ):
            self.last_kwargs = {
                "hash_algorithm": hash_algorithm,
                "marshaling_algorithm": marshaling_algorithm,
            }
            data = base64.b64decode(hash_input)
            raw = priv.sign(data)  # genuine 64-byte Ed25519 signature
            if override_payload is not None:
                payload = override_payload
            elif marshaling_algorithm == "jws" and hash_algorithm == "none":
                payload = raw
            else:
                # Emulate Vault's asn1 marshaling: a DER-wrapped (non-raw) blob
                # that the local raw-Ed25519 verify() will reject.
                payload = encode_dss_signature(
                    int.from_bytes(raw[:32], "big"),
                    int.from_bytes(raw[32:], "big"),
                )
            return {
                "data": {
                    "signature": "vault:v1:" + base64.b64encode(payload).decode("ascii")
                }
            }

    transit = _FakeTransit()

    class _FakeClient:
        def __init__(self, *a, **k):
            self.secrets = types.SimpleNamespace(transit=transit)

        def is_authenticated(self):
            return True

    fake = types.ModuleType("hvac")
    fake.Client = _FakeClient
    monkeypatch.setitem(sys.modules, "hvac", fake)
    return transit


def _make_provider(monkeypatch, priv, **fake_kwargs):
    _install_fake_hvac(monkeypatch, priv, **fake_kwargs)
    from trustchain.kms import VaultTransitKeyProvider

    return VaultTransitKeyProvider(
        url="http://vault:8200", token="root", key_name="trustchain-agent"
    )


def test_sign_returns_raw_64_bytes_and_verifies():
    """Round-trip: sign() must return 64 raw bytes that verify() accepts."""
    priv = ed25519.Ed25519PrivateKey.generate()

    with pytest.MonkeyPatch.context() as mp:
        provider = _make_provider(mp, priv)
        data = b"contribution-event-payload"
        sig = provider.sign(data)

        assert isinstance(sig, (bytes, bytearray))
        assert len(sig) == 64, f"expected raw 64-byte Ed25519 sig, got {len(sig)}"
        # The provider's own local public-key verify must accept its own output.
        assert provider.verify(data, sig) is True
        # Tampered data must not verify (sanity: verify isn't a no-op true).
        assert provider.verify(b"other-data", sig) is False


def test_sign_requests_raw_marshaling_from_vault():
    """sign() must ask Vault for an un-prehashed, raw (jws) signature."""
    priv = ed25519.Ed25519PrivateKey.generate()

    with pytest.MonkeyPatch.context() as mp:
        transit = _install_fake_hvac(mp, priv)
        from trustchain.kms import VaultTransitKeyProvider

        provider = VaultTransitKeyProvider(
            url="http://vault:8200", token="root", key_name="trustchain-agent"
        )
        provider.sign(b"x")

        assert transit.last_kwargs["hash_algorithm"] == "none"
        assert transit.last_kwargs["marshaling_algorithm"] == "jws"


def test_short_signature_is_rejected():
    """A malformed/short Vault response must raise KeyProviderError, not return."""
    from trustchain.kms import KeyProviderError

    priv = ed25519.Ed25519PrivateKey.generate()

    with pytest.MonkeyPatch.context() as mp:
        provider = _make_provider(mp, priv, override_payload=b"too-short")
        with pytest.raises(KeyProviderError):
            provider.sign(b"anything")
