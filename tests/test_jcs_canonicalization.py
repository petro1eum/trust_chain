"""RFC 8785 (JCS) opt-in canonicalization — dual-path, non-breaking (RFC-003).

``canon="jcs"`` signs/verifies via RFC 8785 (the ``rfc8785`` package); ``canon``
absent is the byte-identical legacy scheme. The ``canon`` field is itself signed,
so it cannot be stripped/downgraded. Skipped when ``rfc8785`` is not installed.
"""

from __future__ import annotations

import json

import pytest

from trustchain.receipt import build_receipt
from trustchain.v2.signer import SignedResponse, Signer, _canonical_bytes

rfc8785 = pytest.importorskip("rfc8785")


def test_legacy_canon_is_byte_identical():
    cd = {"tool_id": "t", "data": {"b": 2, "a": 1}, "timestamp": 1.0}
    assert _canonical_bytes(cd, None) == json.dumps(
        cd, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def test_jcs_bytes_match_rfc8785():
    cd = {"b": {"y": 1, "x": "Берлин"}, "a": [3, {"n": 2, "m": 1}]}
    assert _canonical_bytes(cd, "jcs") == rfc8785.dumps(cd)


def test_unknown_canon_raises():
    with pytest.raises(ValueError):
        _canonical_bytes({"a": 1}, "weird")


def test_jcs_sign_verify_roundtrip():
    s = Signer()
    resp = s.sign("weather_api", {"temp": 21, "note": "café"}, canon="jcs")
    assert resp.canon == "jcs"
    assert s.verify(resp) is True
    assert resp.to_dict()["canon"] == "jcs"


def test_legacy_default_still_verifies():
    s = Signer()
    legacy = s.sign("t", {"x": "café"})
    assert legacy.canon is None
    assert s.verify(legacy) is True


def test_jcs_tamper_fails():
    s = Signer()
    resp = s.sign("t", {"x": 1}, canon="jcs")
    d = resp.to_dict()
    d["data"] = {"x": 2}
    assert s.verify(SignedResponse(**d)) is False


def test_canon_downgrade_is_rejected():
    # Stripping canon jcs->absent forces legacy re-canon -> signature must fail.
    s = Signer()
    resp = s.sign("t", {"x": 1}, canon="jcs")
    d = resp.to_dict()
    del d["canon"]
    assert s.verify(SignedResponse(**d)) is False


def test_jcs_receipt_roundtrip():
    s = Signer()
    resp = s.sign("weather_api", {"temp": 21}, canon="jcs")
    res = build_receipt(resp, s.get_public_key(), key_id=s.key_id).verify()
    assert res.signature_ok is True
    assert res.valid is True
