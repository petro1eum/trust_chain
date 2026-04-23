"""Tool manifest canonical hash."""

from pathlib import Path

from typer.testing import CliRunner

from trustchain.cli import app
from trustchain.v3.manifest_hash import tool_manifest_sha256_hex


def test_tool_manifest_sha256_order_independent() -> None:
    a = {"version": "1.0.0", "name": "t", "publisher": "p"}
    b = {"publisher": "p", "name": "t", "version": "1.0.0"}
    assert tool_manifest_sha256_hex(a) == tool_manifest_sha256_hex(b)


def test_cli_manifest_hash(tmp_path: Path) -> None:
    p = tmp_path / "m.json"
    p.write_text('{"name":"x","version":"1.0.0","publisher":"y"}\n', encoding="utf-8")
    r = CliRunner().invoke(app, ["manifest", "hash", str(p)])
    assert r.exit_code == 0, r.stdout + r.stderr
    h = r.stdout.strip()
    assert len(h) == 64
    assert h == tool_manifest_sha256_hex(
        {"name": "x", "version": "1.0.0", "publisher": "y"}
    )
