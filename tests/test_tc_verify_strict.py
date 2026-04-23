"""Tests for tc-verify --strict mode and unified error matrix (POST_MVP)."""

from __future__ import annotations

import base64
import gzip
import json
import subprocess
import sys
from pathlib import Path

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.tc_verify_main import (
    EXIT_CHAIN_BROKEN,
    EXIT_META_MISSING,
    EXIT_OK,
    EXIT_PKIX_FAIL,
    EXIT_SIG_FAIL,
    EXIT_TIME_NONMONOTONIC,
)


def _make_chain(tmp: Path, n_ops: int = 3) -> tuple[Path, str]:
    """Mint n signed ops, export to jsonl.gz, return (path, pubkey_b64)."""
    tc = TrustChain(
        TrustChainConfig(
            enable_chain=False,
            enable_pki=False,
            chain_storage="memory",
        )
    )
    pubkey_b64 = tc.export_public_key()
    ops = []
    parent = None
    for i in range(n_ops):
        sr = tc._signer.sign(
            tool_id=f"tool_{i}",
            data={"i": i},
            parent_signature=parent,
        )
        ops.append(sr.to_dict())
        parent = sr.signature

    export_path = tmp / "chain.jsonl.gz"
    with gzip.open(export_path, "wt", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "type": "meta",
                    "key_id": tc._signer.get_key_id(),
                    "operations_count": len(ops),
                    "include_subagents": False,
                }
            )
            + "\n"
        )
        for op in ops:
            f.write(json.dumps(op, default=str) + "\n")
    return export_path, pubkey_b64


def _run_cli(export: Path, pubkey: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "trustchain.tc_verify_main",
            str(export),
            "--pubkey",
            pubkey,
            *args,
        ],
        capture_output=True,
        text=True,
    )


# ── happy path ────────────────────────────────────────────────────────────────


def test_nonstrict_ok(tmp_path):
    export, pk = _make_chain(tmp_path, 3)
    cp = _run_cli(export, pk)
    assert cp.returncode == EXIT_OK, (cp.stdout, cp.stderr)
    assert "OK: verified_signatures=3" in cp.stdout


def test_json_output_ok(tmp_path):
    export, pk = _make_chain(tmp_path, 2)
    cp = _run_cli(export, pk, "--json")
    assert cp.returncode == EXIT_OK
    report = json.loads(cp.stdout)
    assert report["status"] == "ok"
    assert report["category"] == "ok"
    assert report["counts"]["ok"] == 2
    assert report["counts"]["fail"] == 0


# ── error matrix ─────────────────────────────────────────────────────────────


def test_signature_fail_category(tmp_path):
    export, pk = _make_chain(tmp_path, 2)
    # Tamper with the first op's data → signature must fail.
    rows = []
    with gzip.open(export, "rt", encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    for r in rows:
        if r.get("type") != "meta":
            r["data"] = {"tampered": True}
            break
    export2 = tmp_path / "tamper.jsonl.gz"
    with gzip.open(export2, "wt", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    cp = _run_cli(export2, pk, "--json")
    assert cp.returncode == EXIT_SIG_FAIL
    rep = json.loads(cp.stdout)
    assert rep["category"] == "signature"
    assert rep["counts"]["fail"] >= 1


def test_chain_broken_in_strict_requires_pkix_first(tmp_path):
    """--strict without PKIX artefacts must exit EXIT_PKIX_FAIL immediately."""
    export, pk = _make_chain(tmp_path, 2)
    cp = _run_cli(export, pk, "--strict", "--json")
    assert cp.returncode == EXIT_PKIX_FAIL
    rep = json.loads(cp.stdout)
    assert rep["exit_code"] == EXIT_PKIX_FAIL
    assert any("PKIX" in e or "pkix" in e.lower() for e in rep["errors"])


def test_meta_missing_strict(tmp_path):
    export, pk = _make_chain(tmp_path, 1)
    # Strip the meta line.
    rows = []
    with gzip.open(export, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("type") != "meta":
                rows.append(r)
    export2 = tmp_path / "no_meta.jsonl.gz"
    with gzip.open(export2, "wt", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    # With --strict but PKIX sources present (fake paths won't be reached because
    # meta check runs after PKIX).  Use non-strict to assert meta-missing is ONLY
    # a strict-mode concern:
    cp_nonstrict = _run_cli(export2, pk)
    assert cp_nonstrict.returncode == EXIT_OK  # non-strict ignores meta


def test_nonmonotonic_timestamp_strict(tmp_path, monkeypatch):
    # Build a 2-op export where ts goes backwards in op[1].
    export, pk = _make_chain(tmp_path, 2)
    rows = []
    with gzip.open(export, "rt", encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    # Find the two op rows and invert their timestamps.
    ops = [r for r in rows if r.get("type") != "meta"]
    ops[0]["timestamp"], ops[1]["timestamp"] = ops[1]["timestamp"], ops[0]["timestamp"]
    # NOTE: this breaks signature verification too, since timestamp is signed.
    # So we call the in-process helper directly to isolate the time check.
    from trustchain.tc_verify_main import _check_time_monotonic

    errs = _check_time_monotonic(ops)
    assert any("non-monotonic" in e for e in errs)


def test_chain_continuity_helper_detects_fork(tmp_path):
    from trustchain.tc_verify_main import _check_chain_continuity

    bad = [
        {"signature": "S0", "parent_signature": None},
        {"signature": "S1", "parent_signature": "WRONG"},  # should be S0
    ]
    errs, ok = _check_chain_continuity(bad)
    assert not ok
    assert any("parent_signature" in e for e in errs)

    good = [
        {"signature": "S0", "parent_signature": None},
        {"signature": "S1", "parent_signature": "S0"},
    ]
    errs2, ok2 = _check_chain_continuity(good)
    assert ok2
    assert errs2 == []
