"""WITNESS-1: receipt witness verification must fail closed on a forged co-signature."""

from __future__ import annotations

import base64
import hashlib
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain import build_receipt
from trustchain.v2.signer import Signer
from trustchain.v2.witness import CoSignedTreeHead, sign_tree_head


def _ed25519():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return priv, pub


def _valid_cosign():
    log_priv, log_pub = _ed25519()
    root = hashlib.sha256(b"leaf").hexdigest()
    sth = sign_tree_head(
        log_id="log-1",
        tree_size=1,
        root_hash=root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    wit_priv, wit_pub = _ed25519()
    # CoSignedTreeHead is frozen; sign its digest (= sha256(sth.digest()||witness_id)) up front.
    digest = hashlib.sha256(sth.digest() + b"w1").digest()
    return CoSignedTreeHead(
        sth=sth,
        witness_id="w1",
        witness_public_key=base64.b64encode(wit_pub).decode("ascii"),
        witness_signature=base64.b64encode(wit_priv.sign(digest)).decode("ascii"),
        observed_at=time.time(),
    )


def _receipt_with_witness(witness_dict):
    signer = Signer()
    resp = signer.sign(
        tool_id="weather_service", data={"location": "London", "temp": 22}
    )
    r = build_receipt(resp, signer.get_public_key(), key_id=signer.get_key_id())
    r.witnesses = [witness_dict]
    return r


def test_valid_cosignature_passes():
    r = _receipt_with_witness(_valid_cosign().to_dict())
    v = r.verify(verify_witnesses=True)
    assert v.witnesses_ok is True, v.errors


def test_forged_cosignature_fails_closed():
    bad = _valid_cosign().to_dict()
    raw = bytearray(base64.b64decode(bad["witness_signature"]))
    raw[0] ^= 0x01  # flip one byte of the witness signature
    bad["witness_signature"] = base64.b64encode(bytes(raw)).decode("ascii")
    r = _receipt_with_witness(bad)
    v = r.verify(verify_witnesses=True)
    assert v.witnesses_ok is False  # was True before the fix (fail-open)
    assert v.valid is False
