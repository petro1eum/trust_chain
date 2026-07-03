"""Historical (as-of) validity for tc-verify — non-breaking, opt-in (RFC-003).

Default behavior (as_of/at = None) is unchanged: cert validity is checked at
'now' and ANY revocation invalidates. With an as-of instant, a signature made
while the cert was valid survives later expiry, and revocation invalidates it
only if dated at/before that instant OR the reason is key/CA compromise.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from trustchain.tc_verify_main import _assert_cert_valid_now, _assert_not_revoked

_SERIAL = 12345
_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "asof-test")])


def _cert(sk: Ed25519PrivateKey, nb: datetime, na: datetime) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_NAME)
        .issuer_name(_NAME)
        .public_key(sk.public_key())
        .serial_number(_SERIAL)
        .not_valid_before(nb)
        .not_valid_after(na)
        .sign(sk, None)
    )


def _crl_pem(
    sk: Ed25519PrivateKey, rev_date: datetime, reason: x509.ReasonFlags
) -> str:
    now = datetime.now(timezone.utc)
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(_SERIAL)
        .revocation_date(rev_date)
        .add_extension(x509.CRLReason(reason), critical=False)
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_NAME)
        .last_update(now)
        .next_update(now + timedelta(days=1))
        .add_revoked_certificate(revoked)
        .sign(sk, None)
    )
    return crl.public_bytes(serialization.Encoding.PEM).decode()


# ── validity window ──────────────────────────────────────────────────────────


def test_default_rejects_expired_cert():
    sk = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    cert = _cert(sk, now - timedelta(hours=2), now - timedelta(hours=1))  # expired
    with pytest.raises(ValueError):
        _assert_cert_valid_now(cert, "agent")  # default: check at 'now'


def test_as_of_accepts_cert_valid_at_signing_time():
    sk = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    cert = _cert(sk, now - timedelta(hours=2), now - timedelta(hours=1))  # expired now
    signing_time = now - timedelta(minutes=90)  # was within the window then
    _assert_cert_valid_now(cert, "agent", at=signing_time)  # must NOT raise


# ── revocation ───────────────────────────────────────────────────────────────


def test_default_any_revocation_fails():
    sk = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    cert = _cert(sk, now - timedelta(days=1), now + timedelta(days=1))
    crl = _crl_pem(sk, now - timedelta(minutes=30), x509.ReasonFlags.superseded)
    with pytest.raises(ValueError):
        _assert_not_revoked(cert, crl)  # default: on CRL => fail


def test_revoked_after_signing_survives_historical():
    sk = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    cert = _cert(sk, now - timedelta(days=1), now + timedelta(days=1))
    signing_time = now - timedelta(hours=1)
    crl = _crl_pem(sk, now - timedelta(minutes=30), x509.ReasonFlags.superseded)
    # signed BEFORE revocation, reason is not compromise => still valid as-of signing
    _assert_not_revoked(cert, crl, as_of=signing_time)  # must NOT raise


def test_revoked_before_signing_fails_historical():
    sk = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    cert = _cert(sk, now - timedelta(days=1), now + timedelta(days=1))
    signing_time = now - timedelta(minutes=10)
    crl = _crl_pem(sk, now - timedelta(hours=1), x509.ReasonFlags.superseded)
    with pytest.raises(ValueError):
        _assert_not_revoked(cert, crl, as_of=signing_time)


def test_key_compromise_is_retroactive():
    sk = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    cert = _cert(sk, now - timedelta(days=1), now + timedelta(days=1))
    signing_time = now - timedelta(hours=2)  # signed BEFORE revocation
    crl = _crl_pem(sk, now - timedelta(minutes=30), x509.ReasonFlags.key_compromise)
    with pytest.raises(ValueError):
        _assert_not_revoked(cert, crl, as_of=signing_time)  # compromise => retroactive
