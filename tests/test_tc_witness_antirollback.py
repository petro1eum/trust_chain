"""WITNESS-1: tc-witness observe refuses to co-sign a shrunk or forked log (anti-rollback)."""

import argparse
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain.tc_witness_main import _cmd_observe
from trustchain.v2.witness import sign_tree_head


def _ed():
    p = ed25519.Ed25519PrivateKey.generate()
    pub = p.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return p, pub


def _witness_key(tmp_path):
    priv, pub = _ed()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p = tmp_path / "witness.json"
    p.write_text(
        json.dumps(
            {
                "type": "ed25519",
                "witness_id": "w1",
                "private_key": base64.b64encode(seed).decode(),
                "public_key": base64.b64encode(pub).decode(),
                "created_at": time.time(),
            }
        )
    )
    return p


def _sth_file(tmp_path, name, log_priv, log_pub, tree_size, root_hash):
    sth = sign_tree_head(
        log_id="log-1",
        tree_size=tree_size,
        root_hash=root_hash,
        sign_fn=log_priv.sign,
        public_key=log_pub,
    )
    p = tmp_path / name
    p.write_text(json.dumps(sth.to_dict()))
    return p


def _observe(key, sth_input, state, out=None):
    ns = argparse.Namespace(
        key=str(key),
        sth_input=str(sth_input),
        out=str(out) if out else None,
        state=str(state),
    )
    return _cmd_observe(ns)


def test_observe_anti_rollback(tmp_path):
    key = _witness_key(tmp_path)
    state = tmp_path / "state.json"
    log_priv, log_pub = _ed()

    s2 = _sth_file(tmp_path, "s2.json", log_priv, log_pub, 2, "aa" * 32)
    assert _observe(key, s2, state, tmp_path / "c2.json") == 0  # first observation

    s3 = _sth_file(tmp_path, "s3.json", log_priv, log_pub, 3, "bb" * 32)
    assert _observe(key, s3, state, tmp_path / "c3.json") == 0  # monotonic grow OK

    # Shrink (revert) → refuse.
    s1 = _sth_file(tmp_path, "s1.json", log_priv, log_pub, 1, "cc" * 32)
    with pytest.raises(SystemExit):
        _observe(key, s1, state)

    # Fork: different root at an already-observed tree_size → refuse.
    s3_forked = _sth_file(tmp_path, "s3f.json", log_priv, log_pub, 3, "dd" * 32)
    with pytest.raises(SystemExit):
        _observe(key, s3_forked, state)
