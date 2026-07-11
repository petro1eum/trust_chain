"""SPEC-WITNESS-NODE-1 R1/R2 — HTTP witness node contract tests.

Money tests: the node refuses to co-sign a shrunk/forked log, refuses a
consistency proof that is not anchored at its own memory, and its refusals
never advance the persisted state.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain.tc_witness_serve import load_node, make_server
from trustchain.v2 import rfc6962
from trustchain.v2.witness import (
    CoSignedTreeHead,
    sign_tree_head,
    verify_cosigned,
    verify_quorum,
)

LEAVES = [f"op-{i}".encode() for i in range(8)]
ROOT4 = rfc6962.merkle_tree_hash(LEAVES[:4]).hex()
ROOT8 = rfc6962.merkle_tree_hash(LEAVES).hex()
PROOF_4_8 = [h.hex() for h in rfc6962.consistency_proof(4, LEAVES)]


def _make_log_key() -> tuple[Any, bytes]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def _sth(priv: Any, pub: bytes, size: int, root: str, log_id: str = "test-log"):
    return sign_tree_head(
        log_id=log_id,
        tree_size=size,
        root_hash=root,
        sign_fn=priv.sign,
        public_key=pub,
    )


def _write_key_file(tmp_path, witness_id: str = "w1") -> str:
    priv = ed25519.Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_path = tmp_path / "witness.key.json"
    key_path.write_text(
        json.dumps(
            {
                "type": "ed25519",
                "witness_id": witness_id,
                "private_key": base64.b64encode(seed).decode("ascii"),
                "public_key": base64.b64encode(pub).decode("ascii"),
                "created_at": time.time(),
            }
        ),
        encoding="utf-8",
    )
    return str(key_path)


class _Server:
    def __init__(self, tmp_path, **node_kwargs: Any) -> None:
        self.key_path = _write_key_file(tmp_path)
        self.state_path = str(tmp_path / "observed.json")
        self.node = load_node(self.key_path, self.state_path, **node_kwargs)
        self.httpd = make_server(self.node, "127.0.0.1", 0)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def server(tmp_path):
    srv = _Server(tmp_path)
    yield srv
    srv.stop()


@pytest.fixture()
def strict_server(tmp_path):
    srv = _Server(tmp_path, require_consistency=True)
    yield srv
    srv.stop()


def _get(url: str) -> tuple[int, dict[str, Any]]:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _post(url: str, obj: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(
        url,
        data=json.dumps(obj).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_healthz_exposes_identity(server):
    status, body = _get(server.url + "/healthz")
    assert status == 200 and body["ok"] is True
    assert body["witness_id"] == "w1"
    assert base64.b64decode(body["public_key"]) == server.node.public_key


def test_first_observe_cosigns_and_quorum_verifies(server):
    priv, pub = _make_log_key()
    status, body = _post(server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    assert status == 200
    cosig = CoSignedTreeHead.from_dict(body)
    assert verify_cosigned(cosig)
    quorum = verify_quorum(
        [cosig],
        min_witnesses=1,
        trusted_witness_keys={"w1": server.node.public_key},
    )
    assert quorum["ok"] is True


def test_observed_endpoint_roundtrip(server):
    priv, pub = _make_log_key()
    assert _get(server.url + "/observed?log_id=test-log")[0] == 404
    _post(server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    status, entry = _get(server.url + "/observed?log_id=test-log")
    assert status == 200
    assert entry["tree_size"] == 4 and entry["root_hash"] == ROOT4


def test_shrink_refused_and_state_untouched(server):
    priv, pub = _make_log_key()
    _post(server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    status, body = _post(
        server.url + "/observe",
        _sth(priv, pub, 2, rfc6962.merkle_tree_hash(LEAVES[:2]).hex()).to_dict(),
    )
    assert status == 409 and "shrank" in body["error"]
    assert _get(server.url + "/observed?log_id=test-log")[1]["tree_size"] == 4


def test_fork_refused(server):
    priv, pub = _make_log_key()
    _post(server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    forged_root = rfc6962.merkle_tree_hash([b"evil"] + LEAVES[1:4]).hex()
    status, body = _post(
        server.url + "/observe", _sth(priv, pub, 4, forged_root).to_dict()
    )
    assert status == 409 and "fork" in body["error"]


def test_growth_with_valid_proof_cosigned(server):
    priv, pub = _make_log_key()
    _post(server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    status, body = _post(
        server.url + "/observe",
        {
            "sth": _sth(priv, pub, 8, ROOT8).to_dict(),
            "consistency": {
                "old_tree_size": 4,
                "old_root_hash": ROOT4,
                "proof": PROOF_4_8,
            },
        },
    )
    assert status == 200
    assert verify_cosigned(CoSignedTreeHead.from_dict(body))


def test_proof_must_anchor_at_witness_memory(server):
    priv, pub = _make_log_key()
    _post(server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    status, body = _post(
        server.url + "/observe",
        {
            "sth": _sth(priv, pub, 8, ROOT8).to_dict(),
            "consistency": {
                "old_tree_size": 3,  # operator claims a different anchor
                "old_root_hash": rfc6962.merkle_tree_hash(LEAVES[:3]).hex(),
                "proof": [h.hex() for h in rfc6962.consistency_proof(3, LEAVES)],
            },
        },
    )
    assert status == 409 and "anchored" in body["error"]


def test_bad_proof_refused(server):
    priv, pub = _make_log_key()
    _post(server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    bad = list(PROOF_4_8)
    bad[0] = rfc6962.leaf_hash(b"garbage").hex()
    status, body = _post(
        server.url + "/observe",
        {
            "sth": _sth(priv, pub, 8, ROOT8).to_dict(),
            "consistency": {
                "old_tree_size": 4,
                "old_root_hash": ROOT4,
                "proof": bad,
            },
        },
    )
    assert status == 409 and "consistency verification failed" in body["error"]


def test_require_consistency_refuses_bare_growth(strict_server):
    priv, pub = _make_log_key()
    _post(strict_server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    status, body = _post(
        strict_server.url + "/observe", _sth(priv, pub, 8, ROOT8).to_dict()
    )
    assert status == 409 and "required" in body["error"]
    status, _ = _post(
        strict_server.url + "/observe",
        {
            "sth": _sth(priv, pub, 8, ROOT8).to_dict(),
            "consistency": {
                "old_tree_size": 4,
                "old_root_hash": ROOT4,
                "proof": PROOF_4_8,
            },
        },
    )
    assert status == 200


def test_log_key_change_refused_tofu(server):
    priv, pub = _make_log_key()
    _post(server.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    priv2, pub2 = _make_log_key()
    status, body = _post(server.url + "/observe", _sth(priv2, pub2, 8, ROOT8).to_dict())
    assert status == 409 and "key changed" in body["error"]


def test_invalid_log_signature_rejected(server):
    priv, pub = _make_log_key()
    sth = _sth(priv, pub, 4, ROOT4).to_dict()
    sth["tree_size"] = 5  # break the signature binding
    status, body = _post(server.url + "/observe", sth)
    assert status == 400 and "invalid log signature" in body["error"]


def test_idempotent_reanchor_same_head(server):
    priv, pub = _make_log_key()
    sth = _sth(priv, pub, 4, ROOT4).to_dict()
    assert _post(server.url + "/observe", sth)[0] == 200
    assert _post(server.url + "/observe", sth)[0] == 200


def test_state_survives_restart(tmp_path):
    srv = _Server(tmp_path)
    priv, pub = _make_log_key()
    try:
        _post(srv.url + "/observe", _sth(priv, pub, 4, ROOT4).to_dict())
    finally:
        srv.stop()
    node2 = load_node(srv.key_path, srv.state_path)
    status, body = node2.observe(
        _sth(priv, pub, 2, rfc6962.merkle_tree_hash(LEAVES[:2]).hex()).to_dict()
    )
    assert status == 409 and "shrank" in body["error"]


def test_bare_stub_path_compat(server):
    """POST / (no /observe) keeps working for stub-configured clients."""
    priv, pub = _make_log_key()
    status, body = _post(server.url + "/", _sth(priv, pub, 4, ROOT4).to_dict())
    assert status == 200
    assert verify_cosigned(CoSignedTreeHead.from_dict(body))
