"""Attribution extensions: backward-compat + tamper-evidence (RFC-003 follow-up).

Verifies the optional signer_role/custody/input_hash/alg fields are:
  - absent from legacy signatures (byte-identical, no leakage),
  - signed & tamper-evident when present,
  - custody is truthful (derived from the signer, not caller-supplied),
  - carried consistently through the receipt canonicalization.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain.receipt import build_receipt
from trustchain.v2.signer import (
    SignedResponse,
    Signer,
    _canonical_json_from_response,
    canonical_input_hash,
)


def test_legacy_sign_has_no_attribution_fields():
    """A plain sign() must not leak the new keys into the signed payload."""
    s = Signer()
    resp = s.sign("weather_api", {"temp": 21})
    assert s.verify(resp) is True
    canonical = _canonical_json_from_response(resp, include_signature_id=True)
    for key in ("signer_role", "custody", "input_hash", "alg"):
        assert key not in canonical
        assert key not in resp.to_dict()


def test_attribution_roundtrip_verifies():
    s = Signer()
    resp = s.sign(
        "weather_api",
        {"temp": 21},
        signer_role="tool",
        input_hash=canonical_input_hash({"city": "Berlin"}),
        alg="ed25519",
        bind_custody=True,
    )
    assert s.verify(resp) is True
    d = resp.to_dict()
    assert d["signer_role"] == "tool"
    assert d["custody"]["type"] == "software"
    assert d["input_hash"].startswith("sha256:")
    assert d["alg"] == "ed25519"


def test_custody_is_truthful_software_by_default():
    s = Signer()
    resp = s.sign("t", {"x": 1}, bind_custody=True)
    assert resp.custody == {"type": "software", "key_id": s.key_id}


class _StubProvider:
    """Minimal hard-KMS provider backed by a real Ed25519 key (seed never leaves)."""

    def __init__(self):
        self._sk = ed25519.Ed25519PrivateKey.generate()

    def get_key_id(self):
        return "kms-key-1"

    def get_public_key(self):
        return self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload):
        return self._sk.sign(payload)


def test_custody_reflects_hard_kms_provider():
    s = Signer.from_provider(_StubProvider())
    resp = s.sign("t", {"x": 1}, bind_custody=True)
    assert resp.custody["type"] == "hard_kms"
    assert resp.custody["provider"] == "_StubProvider"
    assert s.verify(resp) is True  # delegated signature still verifies


def _tamper(resp, **changes):
    d = resp.to_dict()
    d.update(changes)
    return SignedResponse(**d)


def test_tamper_signer_role_fails():
    s = Signer()
    resp = s.sign("t", {"x": 1}, signer_role="tool", bind_custody=True)
    assert s.verify(_tamper(resp, signer_role="agent")) is False


def test_tamper_custody_fails():
    s = Signer()
    resp = s.sign("t", {"x": 1}, bind_custody=True)
    forged = {"type": "hard_kms", "key_id": "x"}
    assert s.verify(_tamper(resp, custody=forged)) is False


def test_tamper_input_hash_fails():
    s = Signer()
    resp = s.sign("t", {"x": 1}, input_hash=canonical_input_hash({"a": 1}))
    assert s.verify(_tamper(resp, input_hash="sha256:deadbeef")) is False


def test_canonical_input_hash_is_order_independent():
    a = canonical_input_hash({"city": "Berlin", "units": "c"})
    b = canonical_input_hash({"units": "c", "city": "Berlin"})
    assert a == b
    assert a != canonical_input_hash({"city": "Berln", "units": "c"})


def test_receipt_carries_and_binds_attribution():
    s = Signer()
    resp = s.sign(
        "weather_api",
        {"temp": 21},
        signer_role="tool",
        input_hash=canonical_input_hash({"city": "Berlin"}),
        bind_custody=True,
    )
    receipt = build_receipt(resp, s.get_public_key(), key_id=s.key_id)
    assert receipt.envelope["custody"]["type"] == "software"
    assert receipt.verify().signature_ok is True
    # tamper custody in the receipt envelope -> receipt signature must fail
    receipt.envelope["custody"] = {"type": "hard_kms", "key_id": "forged"}
    assert receipt.verify().signature_ok is False
