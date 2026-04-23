"""v2 → v3 linear migration and CAS integrity."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trustchain.cli import app
from trustchain.v3.migrate_v2 import migrate_v2_linear_to_v3, migration_state_path
from trustchain.v3.objects import Commit, Tree, cas_path


def test_commit_digest_matches_written_bytes(tmp_path: Path) -> None:
    tree = Tree(entries={"a": "b" * 64})
    assert tree.digest == Tree(entries={"a": "b" * 64}).digest
    c = Commit(
        tree_digest=tree.digest,
        parents=(),
        message="m",
        metadata={"k": 1},
    )
    p = c.write(tmp_path)
    raw = p.read_bytes()
    from trustchain.v3.objects import _sha256_hex

    assert c.digest == _sha256_hex(raw)


def test_migrate_dry_run_no_cas_hex_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert CliRunner().invoke(app, ["init", "-o", "."]).exit_code == 0
    from trustchain import TrustChain, TrustChainConfig

    tc = TrustChain(
        TrustChainConfig(
            enable_chain=True,
            chain_storage="file",
            chain_dir=".trustchain",
        )
    )
    tc.sign("x", {"n": 1})
    report, _ = migrate_v2_linear_to_v3(tmp_path / ".trustchain", apply=False)
    assert report["v2_ops"] == 1
    assert report["commits"] == 1
    assert report["apply"] is False
    assert len(report["tip_commit"]) == 64
    hex_dirs = [
        p for p in (tmp_path / ".trustchain" / "objects").iterdir() if p.is_dir()
    ]
    assert not any(
        len(p.name) == 2 and all(c in "0123456789abcdef" for c in p.name.lower())
        for p in hex_dirs
    )


def test_migrate_apply_writes_state_and_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert CliRunner().invoke(app, ["init", "-o", "."]).exit_code == 0
    from trustchain import TrustChain, TrustChainConfig

    root = tmp_path / ".trustchain"
    tc = TrustChain(
        TrustChainConfig(
            enable_chain=True,
            chain_storage="file",
            chain_dir=str(root),
        )
    )
    tc.sign("a", {})
    tc.sign("b", {})
    report, _ = migrate_v2_linear_to_v3(root, apply=True)
    assert report["apply"] is True
    tip = report["tip_commit"]
    assert isinstance(tip, str) and len(tip) == 64
    assert cas_path(root, tip).is_file()
    st = migration_state_path(root)
    assert st.is_file()
    data = json.loads(st.read_text(encoding="utf-8"))
    assert data["source_v2_ops"] == 2
    assert data["tip_commit"] == tip
    ref = root / "refs" / "v3" / "main"
    assert ref.read_text(encoding="utf-8").strip() == tip


def test_show_cli_reads_v3_commit_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
    from trustchain import TrustChain, TrustChainConfig

    TrustChain(
        TrustChainConfig(
            enable_chain=True,
            chain_storage="file",
            chain_dir=".trustchain",
        )
    ).sign("one", {})
    assert (
        runner.invoke(app, ["migrate-v3", "-d", ".trustchain", "--apply"]).exit_code
        == 0
    )
    st = json.loads(
        (tmp_path / ".trustchain" / "v3" / "migration_state.json").read_text(
            encoding="utf-8"
        )
    )
    tip = st["tip_commit"]
    r = runner.invoke(app, ["show", tip, "-d", ".trustchain"])
    assert r.exit_code == 0, r.stdout + r.stderr
    assert '"type": "commit"' in r.stdout


def test_log_v3_after_migrate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
    from trustchain import TrustChain, TrustChainConfig

    tc = TrustChain(
        TrustChainConfig(
            enable_chain=True,
            chain_storage="file",
            chain_dir=".trustchain",
        )
    )
    tc.sign("u", {})
    assert (
        runner.invoke(app, ["migrate-v3", "-d", ".trustchain", "--apply"]).exit_code
        == 0
    )
    r = runner.invoke(app, ["log", "--v3", "-n", "5", "-d", ".trustchain"])
    assert r.exit_code == 0, r.stdout + r.stderr
    assert "u" in r.stdout or "op_" in r.stdout


def test_migrate_v3_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
    from trustchain import TrustChain, TrustChainConfig

    TrustChain(
        TrustChainConfig(
            enable_chain=True,
            chain_storage="file",
            chain_dir=".trustchain",
        )
    ).sign("cli", {})
    r0 = runner.invoke(app, ["migrate-v3", "-d", ".trustchain"])
    assert r0.exit_code == 0
    assert "dry-run" in r0.stdout.lower() or "tip_commit" in r0.stdout
    r1 = runner.invoke(app, ["migrate-v3", "-d", ".trustchain", "--apply"])
    assert r1.exit_code == 0
    assert (tmp_path / ".trustchain" / "v3" / "migration_state.json").is_file()
