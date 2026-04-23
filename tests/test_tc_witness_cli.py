"""CLI ``tc-witness``: init / observe / verify / quorum end-to-end."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from trustchain.tc_witness_main import main as tc_witness_main
from trustchain.v2.witness import sign_tree_head


def _log_sth(log_id: str, tree_size: int, root_hash: str):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sth = sign_tree_head(
        log_id=log_id,
        tree_size=tree_size,
        root_hash=root_hash,
        sign_fn=priv.sign,
        public_key=pub,
    )
    return sth


def test_init_creates_witness_key(tmp_path):
    key_path = tmp_path / "w.json"
    rc = tc_witness_main(["init", "--id", "mystaff", "--key", str(key_path)])
    assert rc == 0
    data = json.loads(key_path.read_text("utf-8"))
    assert data["type"] == "ed25519"
    assert data["witness_id"] == "mystaff"
    assert len(base64.b64decode(data["public_key"])) == 32


def test_init_refuses_overwrite_without_force(tmp_path, capsys):
    key_path = tmp_path / "w.json"
    tc_witness_main(["init", "--id", "a", "--key", str(key_path)])
    with pytest.raises(SystemExit):
        tc_witness_main(["init", "--id", "a", "--key", str(key_path)])


def test_observe_and_verify_cycle(tmp_path):
    key_path = tmp_path / "w.json"
    tc_witness_main(["init", "--id", "w1", "--key", str(key_path)])

    sth = _log_sth("L", 3, "deadbeef")
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(json.dumps(sth.to_dict()), "utf-8")

    out_path = tmp_path / "cos.json"
    rc = tc_witness_main(
        [
            "observe",
            "--key",
            str(key_path),
            "--sth-input",
            str(sth_path),
            "--out",
            str(out_path),
        ]
    )
    assert rc == 0
    assert out_path.exists()

    rc2 = tc_witness_main(["verify", str(out_path)])
    assert rc2 == 0


def test_observe_rejects_forged_log_sth(tmp_path):
    """STH с ломаной подписью log-оператора → observe падает с non-zero."""
    key_path = tmp_path / "w.json"
    tc_witness_main(["init", "--id", "w1", "--key", str(key_path)])

    sth = _log_sth("L", 1, "aa")
    d = sth.to_dict()
    d["root_hash"] = "FAKE"  # инвалидирует подпись
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(json.dumps(d), "utf-8")

    with pytest.raises(SystemExit) as exc:
        tc_witness_main(
            [
                "observe",
                "--key",
                str(key_path),
                "--sth-input",
                str(sth_path),
            ]
        )
    assert exc.value.code == 3


def test_quorum_k_of_n(tmp_path):
    # Три witness-а подписывают один и тот же STH.
    sth = _log_sth("L", 1, "ROOT123")
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(json.dumps(sth.to_dict()), "utf-8")

    trusted: dict[str, str] = {}
    cosig_paths: list[str] = []
    for wid in ("w1", "w2", "w3"):
        key_path = tmp_path / f"{wid}.json"
        tc_witness_main(["init", "--id", wid, "--key", str(key_path)])
        trusted[wid] = json.loads(key_path.read_text("utf-8"))["public_key"]
        out = tmp_path / f"{wid}.cos.json"
        tc_witness_main(
            [
                "observe",
                "--key",
                str(key_path),
                "--sth-input",
                str(sth_path),
                "--out",
                str(out),
            ]
        )
        cosig_paths.append(str(out))

    trusted_path = tmp_path / "trusted.json"
    trusted_path.write_text(json.dumps(trusted), "utf-8")
    rc = tc_witness_main(
        [
            "quorum",
            "--trusted",
            str(trusted_path),
            "--min",
            "2",
            *cosig_paths,
        ]
    )
    assert rc == 0


def test_quorum_fails_below_threshold(tmp_path):
    sth = _log_sth("L", 1, "ROOT_SHORT")
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(json.dumps(sth.to_dict()), "utf-8")

    trusted: dict[str, str] = {}
    cosig_paths: list[str] = []
    # Only 1 witness → min=2 won't pass.
    for wid in ("w1",):
        key_path = tmp_path / f"{wid}.json"
        tc_witness_main(["init", "--id", wid, "--key", str(key_path)])
        trusted[wid] = json.loads(key_path.read_text("utf-8"))["public_key"]
        out = tmp_path / f"{wid}.cos.json"
        tc_witness_main(
            [
                "observe",
                "--key",
                str(key_path),
                "--sth-input",
                str(sth_path),
                "--out",
                str(out),
            ]
        )
        cosig_paths.append(str(out))

    trusted_path = tmp_path / "trusted.json"
    trusted_path.write_text(json.dumps(trusted), "utf-8")
    rc = tc_witness_main(
        [
            "quorum",
            "--trusted",
            str(trusted_path),
            "--min",
            "2",
            *cosig_paths,
        ]
    )
    assert rc != 0
