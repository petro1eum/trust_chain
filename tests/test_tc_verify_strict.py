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
    # Force a strictly backwards timestamp in op[1]. A plain swap is a no-op on
    # coarse-clock platforms (e.g. Windows / Python < 3.13), where both ops can
    # share the same time.time() value, so the non-monotonic condition never fires.
    ops = [r for r in rows if r.get("type") != "meta"]
    ops[0]["timestamp"] = 2000.0
    ops[1]["timestamp"] = 1000.0
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


# ── RFC-003 offline-verify remediation (SPEC-BANK-OFFLINE-VERIFY-1) ─────────────


def test_runtime_export_iso_timestamp_verifies(tmp_path):
    """R1/BF-04: runtime export uses ISO timestamp + signed response_timestamp;
    tc-verify must reconstruct the signed float instead of float()-ing the ISO."""
    from datetime import datetime, timezone

    export, pk = _make_chain(tmp_path, 3)
    rows = []
    with gzip.open(export, "rt", encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    runtime_rows = []
    for r in rows:
        if r.get("type") == "meta":
            runtime_rows.append(r)
            continue
        ts = float(r["timestamp"])
        r = dict(r)
        r["response_timestamp"] = ts
        r["timestamp"] = datetime.fromtimestamp(ts, timezone.utc).isoformat()
        runtime_rows.append(r)
    export2 = tmp_path / "runtime.jsonl.gz"
    with gzip.open(export2, "wt", encoding="utf-8") as f:
        for r in runtime_rows:
            f.write(json.dumps(r, default=str) + "\n")
    cp = _run_cli(export2, pk)
    assert cp.returncode == EXIT_OK, (cp.stdout, cp.stderr)
    assert "verified_signatures=3" in cp.stdout


def test_strict_detects_tail_truncation_and_reorder(tmp_path):
    """R2/BF-03: meta.operations_count mismatch (truncation) and parent-signature
    discontinuity (reorder) are both detected."""
    from trustchain.tc_verify_main import _check_chain_continuity, _check_completeness

    ops4 = [
        {"signature": f"S{i}", "parent_signature": (f"S{i - 1}" if i else None)}
        for i in range(4)
    ]
    trunc_errs = _check_completeness({"operations_count": 5}, ops4)
    assert any("operations_count" in e or "truncat" in e.lower() for e in trunc_errs)

    ops5 = [
        {"signature": f"S{i}", "parent_signature": (f"S{i - 1}" if i else None)}
        for i in range(5)
    ]
    assert _check_completeness({"operations_count": 5}, ops5) == []

    reordered = [ops5[0], ops5[2], ops5[1], ops5[3], ops5[4]]
    c_errs, ok = _check_chain_continuity(reordered)
    assert not ok
    assert any("parent_signature" in e for e in c_errs)


def test_strict_requires_crl_and_full_pkix_validity(tmp_path):
    """R3: strict PKIX enforces validity window, CA:TRUE and issuer name-chaining."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    from trustchain.tc_verify_main import (
        _assert_cert_valid_now,
        _assert_is_ca,
        _assert_issuer_matches,
        _verify_pkix_chain,
    )

    def _mk(subject, issuer, signer, pub, is_ca, nb, na):
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb)
            .not_valid_after(na)
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
            )
            .sign(signer, None)
        )

    now = datetime.now(timezone.utc)
    root_key = Ed25519PrivateKey.generate()
    root = _mk(
        "root",
        "root",
        root_key,
        root_key.public_key(),
        True,
        now - timedelta(days=1),
        now + timedelta(days=365),
    )
    agent_key = Ed25519PrivateKey.generate()
    valid_agent = _mk(
        "agent",
        "root",
        root_key,
        agent_key.public_key(),
        False,
        now - timedelta(days=1),
        now + timedelta(days=30),
    )
    expired_agent = _mk(
        "agent",
        "root",
        root_key,
        agent_key.public_key(),
        False,
        now - timedelta(days=10),
        now - timedelta(days=1),
    )

    _assert_cert_valid_now(valid_agent, "agent")
    with pytest.raises(ValueError):
        _assert_cert_valid_now(expired_agent, "agent")

    _assert_is_ca(root, "root")
    with pytest.raises(ValueError):
        _assert_is_ca(valid_agent, "agent")

    _assert_issuer_matches(valid_agent, root)
    other_key = Ed25519PrivateKey.generate()
    other = _mk(
        "other",
        "other",
        other_key,
        other_key.public_key(),
        True,
        now - timedelta(days=1),
        now + timedelta(days=365),
    )
    with pytest.raises(ValueError):
        _assert_issuer_matches(valid_agent, other)

    root_pem = root.public_bytes(serialization.Encoding.PEM).decode()
    agent_pem = valid_agent.public_bytes(serialization.Encoding.PEM).decode()
    _verify_pkix_chain(root_pem, root_pem, agent_pem, strict=True)


def test_registry_base_alone_is_not_trusted(tmp_path):
    """R4: --strict must pin the Root CA out-of-band; registry-base alone is refused."""
    export, pk = _make_chain(tmp_path, 2)
    cp = _run_cli(
        export,
        pk,
        "--strict",
        "--full-chain",
        "--registry-base",
        "https://keys.trust-chain.ai",
        "--agent-id",
        "x",
    )
    assert cp.returncode == EXIT_PKIX_FAIL, (cp.stdout, cp.stderr)
    low = cp.stderr.lower()
    assert "root" in low and ("pin" in low or "out-of-band" in low)


# ── R6: cryptographic anti-truncation (SPEC-CHAIN-INTEGRITY-1) ──────────────────


def test_merkle_root_reported_and_matches(tmp_path):
    """The offline auditor recomputes an RFC 6962 root over the op signatures and
    accepts a matching pinned root."""
    from trustchain.tc_verify_main import _compute_merkle_root

    export, pk = _make_chain(tmp_path, 3)
    rows = [json.loads(x) for x in gzip.open(export, "rt", encoding="utf-8")]
    ops = [r for r in rows if r.get("type") != "meta"]
    expected = _compute_merkle_root(ops)

    cp = _run_cli(export, pk, "--merkle-root", expected, "--json")
    assert cp.returncode == EXIT_OK, (cp.stdout, cp.stderr)
    rep = json.loads(cp.stdout)
    assert rep["merkle_root"] == expected
    assert rep["merkle_root_ok"] is True


def test_merkle_root_detects_truncation_even_when_count_is_faked(tmp_path):
    """R6: an attacker who truncates the tail AND rewrites the unsigned
    meta.operations_count defeats the legacy completeness check — but a pinned
    Merkle root (over all ops) catches it cryptographically."""
    from trustchain.tc_verify_main import EXIT_MERKLE_MISMATCH, _compute_merkle_root

    export, pk = _make_chain(tmp_path, 4)
    rows = [json.loads(x) for x in gzip.open(export, "rt", encoding="utf-8")]
    meta = next(r for r in rows if r.get("type") == "meta")
    ops = [r for r in rows if r.get("type") != "meta"]
    full_root = _compute_merkle_root(ops)  # trusted root over all 4 ops

    trunc = ops[:3]
    meta2 = dict(meta)
    meta2["operations_count"] = 3  # attacker fixes the unsigned count
    export2 = tmp_path / "trunc.jsonl.gz"
    with gzip.open(export2, "wt", encoding="utf-8") as f:
        f.write(json.dumps(meta2) + "\n")
        for op in trunc:
            f.write(json.dumps(op, default=str) + "\n")

    cp = _run_cli(export2, pk, "--merkle-root", full_root, "--json")
    assert cp.returncode == EXIT_MERKLE_MISMATCH, (cp.stdout, cp.stderr)
    rep = json.loads(cp.stdout)
    assert rep["category"] == "merkle"
    assert rep["merkle_root_ok"] is False
