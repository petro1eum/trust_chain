"""A .tcreceipt must not carry unsigned envelope fields (RFC-003 follow-up).

_canonical_envelope_bytes signs only a fixed set of known keys, so an extra key
in the envelope would ride along WITHOUT being covered by the signature — a
consumer could read attacker-controlled data from a receipt whose signature
verifies. verify() now rejects such receipts.
"""

from __future__ import annotations

from trustchain.receipt import build_receipt
from trustchain.v2.signer import Signer


def _receipt():
    s = Signer()
    resp = s.sign("weather_api", {"temp": 21})
    return build_receipt(resp, s.get_public_key(), key_id=s.key_id)


def test_wellformed_receipt_is_valid():
    res = _receipt().verify()
    assert res.signature_ok is True
    assert res.valid is True


def test_extra_envelope_field_is_rejected():
    r = _receipt()
    r.envelope["evil"] = "unsigned-smuggled-data"
    res = r.verify()
    # The signature over the known fields is still cryptographically fine...
    assert res.signature_ok is True
    # ...but the receipt is NOT valid: it carries an unsigned field.
    assert res.valid is False
    assert any("unsigned field" in e for e in res.errors)
    assert any("evil" in e for e in res.errors)


def test_attribution_fields_do_not_trip_the_check():
    # signer_role/custody/input_hash/alg are signed keys — a receipt using them
    # must remain valid (they are in the allowed set).
    from trustchain.v2.signer import canonical_input_hash

    s = Signer()
    resp = s.sign(
        "weather_api",
        {"temp": 21},
        signer_role="tool",
        input_hash=canonical_input_hash({"city": "Berlin"}),
        bind_custody=True,
    )
    res = build_receipt(resp, s.get_public_key(), key_id=s.key_id).verify()
    assert res.valid is True
