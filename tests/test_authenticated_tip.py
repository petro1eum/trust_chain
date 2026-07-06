"""Authenticated tip / truncation defense (SPEC-CHAIN-INTEGRITY-1 R5).

With the RFC 6962 scheme the Merkle root commits to the leaf count (R1), and the
operator-signed SignedTreeHead binds {tree_size, root_hash} (witness protocol).
Together they make the tip *authenticated*: a party holding a signed tip detects
truncation because a shorter log can neither reproduce the committed root nor
pass verify() against it — the store's plaintext HEAD cannot be back-filled to
lie about the size.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain.v2.verifiable_log import VerifiableChainStore
from trustchain.v2.witness import sign_tree_head, verify_tree_head


def _gen():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def _fill(store: VerifiableChainStore, start: int, count: int) -> None:
    for i in range(start, start + count):
        store.append(f"t{i}", {"i": i}, f"s{i}")


def test_signed_tip_binds_size_and_root(tmp_path):
    store = VerifiableChainStore(str(tmp_path / "log"), merkle_scheme="rfc6962")
    _fill(store, 0, 5)
    priv, pub = _gen()
    sth = sign_tree_head(
        log_id="L",
        tree_size=store.length,
        root_hash=store.merkle_root,
        sign_fn=priv.sign,
        public_key=pub,
    )
    # The operator signature covers tree_size + root_hash together.
    assert verify_tree_head(sth) is True
    assert sth.tree_size == 5
    assert sth.root_hash == store.merkle_root


def test_truncation_cannot_satisfy_the_signed_tip(tmp_path):
    full = VerifiableChainStore(str(tmp_path / "full"), merkle_scheme="rfc6962")
    _fill(full, 0, 5)
    priv, pub = _gen()
    sth = sign_tree_head(
        log_id="L",
        tree_size=full.length,
        root_hash=full.merkle_root,
        sign_fn=priv.sign,
        public_key=pub,
    )

    # A truncated log holding only the first 3 operations.
    trunc = VerifiableChainStore(str(tmp_path / "trunc"), merkle_scheme="rfc6962")
    _fill(trunc, 0, 3)
    # The size-committing root differs, so the tip's root is unreachable.
    assert trunc.merkle_root != sth.root_hash

    # Even if the attacker rewrites the plaintext HEAD to the signed 5-op root,
    # verify() recomputes the 3-op root from the log and rejects the mismatch —
    # a shorter log can never verify against the authenticated tip.
    (tmp_path / "trunc" / "HEAD").write_text(sth.root_hash, encoding="utf-8")
    reopened = VerifiableChainStore(str(tmp_path / "trunc"), merkle_scheme="rfc6962")
    result = reopened.verify()
    assert result["valid"] is False
    assert reopened.length != sth.tree_size
