"""Witness / co-signer protocol tests (ADR-SEC-006).

Проверяем:

* Happy-path: log подписывает STH, witness co-sign-ит, оба подписи валидны.
* Witness **отказывается** co-sign-ить, если log сократил tree_size (revert).
* Witness **отказывается**, если root_hash для того же tree_size изменился
  (forked history).
* ``verify_quorum`` требует ≥k из N доверенных witnesses на одном и том же
  ``root_hash``.
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain.v2.witness import (
    CoSignedTreeHead,
    SignedTreeHead,
    Witness,
    WitnessError,
    sign_tree_head,
    verify_cosigned,
    verify_quorum,
    verify_tree_head,
)


def _gen_ed25519():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


class FakeLog:
    """Минимальный WitnessableLog для тестов."""

    def __init__(self):
        self._leaves: list[str] = []

    def append(self, leaf_hash: str):
        self._leaves.append(leaf_hash)

    @property
    def length(self) -> int:
        return len(self._leaves)

    @property
    def merkle_root(self) -> str | None:
        if not self._leaves:
            return None
        import hashlib

        acc = hashlib.sha256()
        for leaf in self._leaves:
            acc.update(leaf.encode())
        return acc.hexdigest()

    def consistency_proof(self, old_length: int, old_root: str) -> dict:
        if old_length > self.length:
            return {"consistent": False, "reason": "shrunk"}
        if old_length == 0:
            return {"consistent": True}
        import hashlib

        acc = hashlib.sha256()
        for leaf in self._leaves[:old_length]:
            acc.update(leaf.encode())
        return {
            "consistent": acc.hexdigest() == old_root,
            "old_length": old_length,
            "old_root": old_root,
        }


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_sign_and_verify_tree_head():
    priv, pub = _gen_ed25519()
    sth = sign_tree_head(
        log_id="trustchain-prod",
        tree_size=7,
        root_hash="deadbeef",
        sign_fn=priv.sign,
        public_key=pub,
    )
    assert sth.tree_size == 7
    assert verify_tree_head(sth) is True


def test_verify_tree_head_rejects_tampered_root():
    priv, pub = _gen_ed25519()
    sth = sign_tree_head(
        log_id="l",
        tree_size=1,
        root_hash="abc",
        sign_fn=priv.sign,
        public_key=pub,
    )
    tampered = SignedTreeHead(
        log_id=sth.log_id,
        tree_size=sth.tree_size,
        root_hash="FAKE",
        timestamp=sth.timestamp,
        signature=sth.signature,
        public_key=sth.public_key,
    )
    assert verify_tree_head(tampered) is False


def test_witness_cosigns_first_observation():
    log_priv, log_pub = _gen_ed25519()
    wit_priv, wit_pub = _gen_ed25519()
    log = FakeLog()
    log.append("leaf-1")
    log.append("leaf-2")
    sth = sign_tree_head(
        log_id="L",
        tree_size=log.length,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    w = Witness(witness_id="w1", public_key=wit_pub, sign_fn=wit_priv.sign)
    cosig = w.observe(log, sth)
    assert isinstance(cosig, CoSignedTreeHead)
    assert verify_cosigned(cosig) is True
    assert cosig.sth.root_hash == sth.root_hash


def test_witness_detects_revert():
    """Если log «откатился» (tree_size меньше ранее подписанного),
    witness ДОЛЖЕН отказаться co-sign-ить."""
    log_priv, log_pub = _gen_ed25519()
    wit_priv, wit_pub = _gen_ed25519()
    log = FakeLog()
    for s in ["a", "b", "c"]:
        log.append(s)
    sth1 = sign_tree_head(
        log_id="L",
        tree_size=3,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    w = Witness(witness_id="w1", public_key=wit_pub, sign_fn=wit_priv.sign)
    w.observe(log, sth1)

    # Откатываем — изначально 3, теперь 2.
    log._leaves.pop()
    sth2 = sign_tree_head(
        log_id="L",
        tree_size=2,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    with pytest.raises(WitnessError, match="tree shrunk|consistency proof failed"):
        w.observe(log, sth2)


def test_witness_detects_forked_history():
    """Одинаковый tree_size, разный root_hash (форк истории) → отказ."""
    log_priv, log_pub = _gen_ed25519()
    wit_priv, wit_pub = _gen_ed25519()
    log = FakeLog()
    for s in ["a", "b"]:
        log.append(s)
    sth1 = sign_tree_head(
        log_id="L",
        tree_size=2,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    w = Witness(witness_id="w1", public_key=wit_pub, sign_fn=wit_priv.sign)
    w.observe(log, sth1)

    # Форк: откатываем последний и добавляем другой — tree_size остаётся 2,
    # но root_hash меняется.
    log._leaves.pop()
    log.append("b-prime")
    sth2 = sign_tree_head(
        log_id="L",
        tree_size=2,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    with pytest.raises(WitnessError, match="consistency proof failed"):
        w.observe(log, sth2)


def test_witness_rejects_bad_log_signature():
    """STH с подделанной подписью log-оператора → reject before consistency."""
    _log_priv, log_pub = _gen_ed25519()
    other_priv, _ = _gen_ed25519()
    wit_priv, wit_pub = _gen_ed25519()
    log = FakeLog()
    log.append("a")
    sth = sign_tree_head(
        log_id="L",
        tree_size=log.length,
        root_hash=log.merkle_root,
        # Signs с другим ключом, чем объявленный public_key — нарушение.
        sign_fn=other_priv.sign,
        public_key=log_pub,
    )
    w = Witness(witness_id="w1", public_key=wit_pub, sign_fn=wit_priv.sign)
    with pytest.raises(WitnessError, match="invalid log signature"):
        w.observe(log, sth)


def test_verify_quorum_happy_path():
    log_priv, log_pub = _gen_ed25519()
    log = FakeLog()
    log.append("a")
    sth = sign_tree_head(
        log_id="L",
        tree_size=1,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    cosigs = []
    trusted: dict[str, bytes] = {}
    for wid in ["w1", "w2", "w3"]:
        wp, wpub = _gen_ed25519()
        trusted[wid] = wpub
        w = Witness(witness_id=wid, public_key=wpub, sign_fn=wp.sign)
        cosigs.append(w.observe(log, sth))

    out = verify_quorum(cosigs, min_witnesses=2, trusted_witness_keys=trusted)
    assert out["ok"] is True
    assert out["agreed_root"] == log.merkle_root
    assert set(out["signers"]) >= {"w1", "w2"}


def test_verify_quorum_requires_trusted_keys():
    """Неизвестный ``witness_id`` или mismatch ключа → не учитывается."""
    log_priv, log_pub = _gen_ed25519()
    log = FakeLog()
    log.append("a")
    sth = sign_tree_head(
        log_id="L",
        tree_size=1,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    wp, wpub = _gen_ed25519()
    w = Witness(witness_id="rogue", public_key=wpub, sign_fn=wp.sign)
    cosig = w.observe(log, sth)
    out = verify_quorum(
        [cosig], min_witnesses=1, trusted_witness_keys={"other": b"\x00" * 32}
    )
    assert out["ok"] is False


def test_verify_quorum_different_root_hash():
    """Если два co-sig-а указывают разные root_hash для одного tree_size —
    buckets разные, quorum не достижим."""
    log_priv, log_pub = _gen_ed25519()
    wp1, wpub1 = _gen_ed25519()
    wp2, wpub2 = _gen_ed25519()

    sth_a = sign_tree_head(
        log_id="L",
        tree_size=1,
        root_hash="ROOT_A",
        sign_fn=log_priv.sign,
        public_key=log_pub,
        timestamp=time.time(),
    )
    sth_b = sign_tree_head(
        log_id="L",
        tree_size=1,
        root_hash="ROOT_B",
        sign_fn=log_priv.sign,
        public_key=log_pub,
        timestamp=time.time(),
    )
    # Для целей quorum-теста подписываем co-sig-ы вручную.
    import base64
    import hashlib

    sig_a = wp1.sign(hashlib.sha256(sth_a.digest() + b"w1").digest())
    sig_b = wp2.sign(hashlib.sha256(sth_b.digest() + b"w2").digest())
    cos_a = CoSignedTreeHead(
        sth=sth_a,
        witness_id="w1",
        witness_public_key=base64.b64encode(wpub1).decode(),
        witness_signature=base64.b64encode(sig_a).decode(),
        observed_at=time.time(),
    )
    cos_b = CoSignedTreeHead(
        sth=sth_b,
        witness_id="w2",
        witness_public_key=base64.b64encode(wpub2).decode(),
        witness_signature=base64.b64encode(sig_b).decode(),
        observed_at=time.time(),
    )
    out = verify_quorum(
        [cos_a, cos_b],
        min_witnesses=2,
        trusted_witness_keys={"w1": wpub1, "w2": wpub2},
    )
    assert out["ok"] is False
    assert "quorum not reached" in out["reason"]
    assert "ROOT_A" in out["buckets"]
    assert "ROOT_B" in out["buckets"]


def test_cosigned_roundtrip_json():
    log_priv, log_pub = _gen_ed25519()
    wp, wpub = _gen_ed25519()
    log = FakeLog()
    log.append("x")
    sth = sign_tree_head(
        log_id="L",
        tree_size=1,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    w = Witness(witness_id="w", public_key=wpub, sign_fn=wp.sign)
    cosig = w.observe(log, sth)
    d = cosig.to_dict()
    restored = CoSignedTreeHead.from_dict(d)
    assert verify_cosigned(restored) is True
