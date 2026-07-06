"""Witness verifies RFC 6962 consistency INDEPENDENTLY (SPEC-CHAIN-INTEGRITY-1 R4).

The previous witness trusted the log's self-reported ``{"consistent": bool}`` —
but the operator we defend against controls that flag. These tests prove the
witness now recomputes the append-only invariant itself from the two tree heads
it holds, so a log that rewrote a prefix cannot get co-signed even while lying
``consistent=True``. The legacy (boolean) path is exercised too, unchanged.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain.v2 import rfc6962
from trustchain.v2.verifiable_log import VerifiableChainStore
from trustchain.v2.witness import Witness, WitnessError, sign_tree_head, verify_cosigned


def _gen():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


class FakeRfc6962Log:
    """An rfc6962-scheme log we fully control — used to forge a rewrite."""

    def __init__(self, leaves):
        self._leaves = [x if isinstance(x, bytes) else x.encode() for x in leaves]

    @property
    def length(self) -> int:
        return len(self._leaves)

    @property
    def merkle_root(self):
        if not self._leaves:
            return None
        return rfc6962.merkle_tree_hash(self._leaves).hex()

    def consistency_proof(self, old_length: int, old_root: str) -> dict:
        # Build a proof from OUR (possibly rewritten) leaves and LIE that it is
        # consistent — exactly what a malicious operator would do.
        proof = []
        if 0 < old_length <= self.length:
            proof = [
                h.hex() for h in rfc6962.consistency_proof(old_length, self._leaves)
            ]
        return {
            "scheme": "rfc6962",
            "consistent": True,  # the lie
            "proof": proof,
            "old_length": old_length,
            "old_root": old_root,
            "current_length": self.length,
            "current_root": self.merkle_root,
        }


class FakeLegacyLog:
    """A legacy (no-scheme) log whose boolean the witness still honors."""

    def __init__(self, self_report: bool):
        self._report = self_report

    @property
    def length(self) -> int:
        return 5

    @property
    def merkle_root(self):
        return "ab" * 32

    def consistency_proof(self, old_length: int, old_root: str) -> dict:
        return {"consistent": self._report, "reason": "legacy"}


def _sth(log, log_priv, log_pub, size=None):
    return sign_tree_head(
        log_id="L",
        tree_size=size if size is not None else log.length,
        root_hash=log.merkle_root,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )


def test_witness_cosigns_honest_rfc6962_store(tmp_path):
    log_priv, log_pub = _gen()
    wit_priv, wit_pub = _gen()
    store = VerifiableChainStore(str(tmp_path / "log"), merkle_scheme="rfc6962")
    for i in range(3):
        store.append(tool=f"t{i}", data={"i": i}, signature=f"s{i}")
    w = Witness(witness_id="w1", public_key=wit_pub, sign_fn=wit_priv.sign)
    w.observe(store, _sth(store, log_priv, log_pub))
    for i in range(3, 6):
        store.append(tool=f"t{i}", data={"i": i}, signature=f"s{i}")
    cosig = w.observe(store, _sth(store, log_priv, log_pub))
    assert verify_cosigned(cosig) is True


def test_witness_rejects_rewritten_prefix_despite_true_selfreport():
    log_priv, log_pub = _gen()
    wit_priv, wit_pub = _gen()
    honest = FakeRfc6962Log([b"a", b"b", b"c"])
    w = Witness(witness_id="w1", public_key=wit_pub, sign_fn=wit_priv.sign)
    w.observe(honest, _sth(honest, log_priv, log_pub))  # remembers (3, honest root)

    # Same operator key signs a head whose prefix was rewritten (leaf 1 changed)
    # and extended. The log lies consistent=True, but the witness recomputes.
    forged = FakeRfc6962Log([b"a", b"b-PRIME", b"c", b"d", b"e"])
    with pytest.raises(WitnessError, match="independent RFC 6962 consistency"):
        w.observe(forged, _sth(forged, log_priv, log_pub))


def test_witness_still_honors_legacy_boolean(tmp_path):
    log_priv, log_pub = _gen()
    wit_priv, wit_pub = _gen()
    # First observation of a legacy log (size 5).
    good = FakeLegacyLog(self_report=True)
    w = Witness(witness_id="w1", public_key=wit_pub, sign_fn=wit_priv.sign)
    w.observe(good, _sth(good, log_priv, log_pub))
    # Second observation reporting consistent=True is trusted (legacy path).
    cosig = w.observe(good, _sth(good, log_priv, log_pub))
    assert verify_cosigned(cosig) is True
    # A legacy log that self-reports inconsistent is rejected.
    bad = FakeLegacyLog(self_report=False)
    w2 = Witness(witness_id="w2", public_key=wit_pub, sign_fn=wit_priv.sign)
    w2.observe(bad, _sth(bad, log_priv, log_pub))
    with pytest.raises(WitnessError, match="consistency proof failed"):
        w2.observe(bad, _sth(bad, log_priv, log_pub))
