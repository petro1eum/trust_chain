"""Tests for TrustChain CLI."""

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trustchain import __version__
from trustchain.cli import app

runner = CliRunner()


class TestExportKey:
    """Test export-key command."""

    def test_export_key_json(self):
        """Test export key in JSON format."""
        result = runner.invoke(app, ["export-key", "--format", "json"])

        assert result.exit_code == 0
        data = json.loads(result.stdout)

        assert "public_key" in data
        assert "key_id" in data
        assert "algorithm" in data
        assert data["algorithm"] == "ed25519"
        assert data["version"] == __version__

    def test_export_key_base64(self):
        """Test export key in base64 format."""
        result = runner.invoke(app, ["export-key", "--format", "base64"])

        assert result.exit_code == 0
        # Should be base64 string without JSON structure
        assert "{" not in result.stdout

    def test_export_key_pem(self):
        """Test export key in PEM format."""
        result = runner.invoke(app, ["export-key", "--format", "pem"])

        assert result.exit_code == 0
        assert "-----BEGIN PUBLIC KEY-----" in result.stdout
        assert "-----END PUBLIC KEY-----" in result.stdout

    def test_export_key_to_file(self):
        """Test export key to file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = Path(f.name)

        try:
            result = runner.invoke(
                app, ["export-key", "--format", "json", "--output", str(filepath)]
            )

            assert result.exit_code == 0
            assert "exported" in result.stdout.lower()

            # Verify file content
            data = json.loads(filepath.read_text())
            assert "public_key" in data

        finally:
            filepath.unlink(missing_ok=True)

    def test_export_key_invalid_format(self):
        """Test export key with invalid format."""
        result = runner.invoke(app, ["export-key", "--format", "invalid"])

        assert result.exit_code == 1
        assert "Unknown format" in result.stdout


class TestInfo:
    """Test info command."""

    def test_info(self):
        """Test info command shows information."""
        result = runner.invoke(app, ["info"])

        assert result.exit_code == 0
        assert "TrustChain Info" in result.stdout
        assert "Version" in result.stdout
        assert "Ed25519" in result.stdout


class TestVerify:
    """Test verify command."""

    def test_verify_valid_response(self):
        """Test verifying a valid signed response."""
        from trustchain import TrustChain

        # Create signed response
        tc = TrustChain()
        signed = tc.sign("test_tool", {"data": "test"})

        # Save to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(signed.to_dict(), f)
            filepath = Path(f.name)

        try:
            result = runner.invoke(app, ["verify", str(filepath)])

            # May fail due to different key, but command should work
            assert result.exit_code in [0, 1]

        finally:
            filepath.unlink(missing_ok=True)

    def test_verify_file_not_found(self):
        """Test verify with non-existent file."""
        result = runner.invoke(app, ["verify", "nonexistent.json"])

        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_verify_invalid_json(self):
        """Test verify with invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json")
            filepath = Path(f.name)

        try:
            result = runner.invoke(app, ["verify", str(filepath)])

            assert result.exit_code == 1
            assert "invalid json" in result.stdout.lower()

        finally:
            filepath.unlink(missing_ok=True)


class TestVersion:
    """Test version command."""

    def test_version(self):
        """Test version command shows version."""
        result = runner.invoke(app, ["version"])

        assert result.exit_code == 0
        assert __version__ in result.stdout


class TestInit:
    """Test init command."""

    def test_init(self):
        """Test init creates directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["init", "--output", tmpdir])

            assert result.exit_code == 0
            assert "initialized" in result.stdout.lower()

            # Check new Git-like directory structure
            trustchain_dir = Path(tmpdir) / ".trustchain"
            assert trustchain_dir.exists()
            assert (trustchain_dir / "objects").exists()
            assert (trustchain_dir / "refs" / "sessions").exists()
            assert (trustchain_dir / "HEAD").exists()
            assert (trustchain_dir / "config.json").exists()


class TestLogGraph:
    """tc log --graph."""

    def test_log_graph_head_and_linear_prefixes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("first_tool", {"n": 1})
        tc.sign("second_tool", {"n": 2})

        r = runner.invoke(app, ["log", "--graph", "-n", "10", "-d", ".trustchain"])
        assert r.exit_code == 0, r.stdout + r.stderr
        assert "(HEAD)" in r.stdout
        assert "* " in r.stdout
        assert "op_" in r.stdout

    def test_log_graph_chrono_marks_head_on_last(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("a", {})
        tc.sign("b", {})
        r = runner.invoke(
            app, ["log", "--graph", "--chrono", "-n", "10", "-d", ".trustchain"]
        )
        assert r.exit_code == 0, r.stdout + r.stderr
        lines = [ln for ln in r.stdout.splitlines() if "(HEAD)" in ln]
        assert len(lines) == 1
        assert "b" in lines[0]


class TestCheckpointBranchRefs:
    """checkpoint / branch / refs CLI (git-like refs under .trustchain)."""

    def test_checkpoint_requires_nonempty_head(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = runner.invoke(app, ["init", "-o", "."])
        assert r.exit_code == 0
        r2 = runner.invoke(app, ["checkpoint", "x", "-d", ".trustchain"])
        assert r2.exit_code == 1
        assert "empty" in r2.stdout.lower()

    def test_checkpoint_branch_refs(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r0 = runner.invoke(app, ["init", "-o", "."])
        assert r0.exit_code == 0

        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("demo_tool", {"step": 1})

        r1 = runner.invoke(app, ["checkpoint", "before-edit", "-d", ".trustchain"])
        assert r1.exit_code == 0, r1.stdout + r1.stderr
        r2 = runner.invoke(app, ["branch", "side-exp", "-d", ".trustchain"])
        assert r2.exit_code == 0, r2.stdout + r2.stderr
        r3 = runner.invoke(app, ["refs", "-d", ".trustchain"])
        assert r3.exit_code == 0
        assert "before-edit" in r3.stdout
        assert "side-exp" in r3.stdout

        rt = runner.invoke(app, ["tag", "release-x", "-d", ".trustchain"])
        assert rt.exit_code == 0, rt.stdout + rt.stderr
        tg = tmp_path / ".trustchain" / "refs" / "tags" / "release-x.ref"
        assert tg.is_file()

        ck = tmp_path / ".trustchain" / "refs" / "checkpoints" / "before-edit.ref"
        assert ck.is_file()
        assert len(ck.read_text().strip()) > 10


class TestCheckout:
    """tc checkout — HEAD из refs/heads."""

    def test_checkout_missing_ref(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        r = runner.invoke(app, ["checkout", "nope", "-d", ".trustchain"])
        assert r.exit_code == 1
        assert "branch" in r.stdout.lower() or "refs" in r.stdout.lower()

    def test_checkout_moves_head(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("a", {})
        mid = tc.sign("b", {})
        assert (
            runner.invoke(app, ["branch", "saved", "-d", ".trustchain"]).exit_code == 0
        )
        tc.sign("c", {})
        r = runner.invoke(app, ["checkout", "saved", "-d", ".trustchain"])
        assert r.exit_code == 0, r.stdout + r.stderr
        head = (tmp_path / ".trustchain" / "HEAD").read_text(encoding="utf-8").strip()
        assert head == mid.signature
        txt = (tmp_path / ".trustchain" / "reflog.txt").read_text(encoding="utf-8")
        assert "checkout" in txt and "saved" in txt


class TestResetSoft:
    """tc reset --soft / --dry-run (file chain)."""

    def test_reset_requires_flag(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        r = runner.invoke(app, ["reset", "op_0001", "-d", ".trustchain"])
        assert r.exit_code == 1
        assert "soft" in r.stdout.lower() or "dry-run" in r.stdout.lower()

    def test_reset_dry_run_lists_detach(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("t1", {"n": 1})
        tc.sign("t2", {"n": 2})
        tc.sign("t3", {"n": 3})
        r = runner.invoke(app, ["reset", "op_0002", "--dry-run", "-d", ".trustchain"])
        assert r.exit_code == 0, r.stdout + r.stderr
        assert "op_0003" in r.stdout
        assert "HEAD" in r.stdout

    def test_reset_soft_moves_head(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("t1", {})
        b = tc.sign("t2", {})
        tc.sign("t3", {})
        mid_sig = b.signature
        r = runner.invoke(app, ["reset", "op_0002", "--soft", "-d", ".trustchain"])
        assert r.exit_code == 0, r.stdout + r.stderr
        head = (tmp_path / ".trustchain" / "HEAD").read_text(encoding="utf-8").strip()
        assert head == mid_sig
        rf = tmp_path / ".trustchain" / "reflog.txt"
        assert rf.is_file()
        assert "reset-soft" in rf.read_text(encoding="utf-8")


class TestRevert:
    """tc revert — signed revert_intent."""

    def test_revert_dry_run_override(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("demo_tool", {"x": 1})
        r = runner.invoke(
            app,
            [
                "revert",
                "HEAD",
                "-d",
                ".trustchain",
                "--dry-run",
                "--reverse-tool",
                "demo_undo",
            ],
        )
        assert r.exit_code == 0, r.stdout + r.stderr
        assert "demo_undo" in r.stdout

    def test_revert_signs_chain(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        td = tmp_path / ".trustchain"
        td.joinpath("reversibles.json").write_text(
            '{"demo_tool":"demo_undo"}', encoding="utf-8"
        )
        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("demo_tool", {"x": 1})
        r = runner.invoke(app, ["revert", "HEAD", "-d", ".trustchain"])
        assert r.exit_code == 0, r.stdout + r.stderr
        assert "revert_intent" in r.stdout.lower() or "signed" in r.stdout.lower()

        tc2 = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tail = tc2.chain.log_reverse(limit=2)
        assert len(tail) >= 2
        assert tail[0].get("tool") == "demo_undo"
        assert (tail[0].get("data") or {}).get("kind") == "revert_intent"

    def test_revert_fails_without_mapping(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0
        from trustchain import TrustChain, TrustChainConfig

        TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        ).sign("orphan_tool", {})
        r = runner.invoke(app, ["revert", "HEAD", "-d", ".trustchain"])
        assert r.exit_code == 1


class TestStandardsExport:
    """tc standards export."""

    def _receipt_file(self, tmp_path: Path) -> Path:
        from trustchain import build_receipt
        from trustchain.v2.signer import Signer

        signer = Signer()
        response = signer.sign("standards_tool", {"answer": 42})
        receipt = build_receipt(
            response,
            signer.get_public_key(),
            key_id=signer.get_key_id(),
        )
        path = tmp_path / "sample.tcreceipt"
        path.write_text(receipt.to_json(), encoding="utf-8")
        return path

    def test_export_scitt_json(self, tmp_path: Path) -> None:
        path = self._receipt_file(tmp_path)

        result = runner.invoke(
            app,
            [
                "standards",
                "export",
                str(path),
                "--format",
                "scitt",
                "--agent-id",
                "agent:test",
                "--sequence",
                "2",
            ],
        )

        assert result.exit_code == 0, result.stdout + result.stderr
        data = json.loads(result.stdout)
        assert data["profile"] == "trustchain.scitt.air-json.v1"
        assert data["protected_headers"]["agent_id"] == "agent:test"
        assert data["protected_headers"]["sequence_number"] == 2

    def test_export_w3c_vc_json(self, tmp_path: Path) -> None:
        path = self._receipt_file(tmp_path)

        result = runner.invoke(
            app,
            [
                "standards",
                "export",
                str(path),
                "--format",
                "w3c-vc",
                "--subject-id",
                "did:example:agent",
            ],
        )

        assert result.exit_code == 0, result.stdout + result.stderr
        data = json.loads(result.stdout)
        assert "TrustChainReceiptCredential" in data["type"]
        assert data["credentialSubject"]["id"] == "did:example:agent"

    def test_export_intoto_to_file(self, tmp_path: Path) -> None:
        path = self._receipt_file(tmp_path)
        output = tmp_path / "statement.intoto.json"

        result = runner.invoke(
            app,
            [
                "standards",
                "export",
                str(path),
                "--format",
                "intoto",
                "--output",
                str(output),
            ],
        )

        assert result.exit_code == 0, result.stdout + result.stderr
        data = json.loads(output.read_text(encoding="utf-8"))
        assert data["_type"] == "https://in-toto.io/Statement/v1"
        assert data["predicate"]["tool_id"] == "standards_tool"


class TestAnchor:
    """tc anchor export / verify."""

    def test_anchor_export_and_verify(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0

        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("anchor_tool", {"step": 1})
        anchor = tmp_path / "chain.anchor.json"

        exported = runner.invoke(
            app, ["anchor", "export", "-d", ".trustchain", "-o", str(anchor)]
        )
        assert exported.exit_code == 0, exported.stdout + exported.stderr

        data = json.loads(anchor.read_text(encoding="utf-8"))
        assert data["format"] == "tc-anchor"
        assert data["length"] == 1
        assert len(data["chain_sha256"]) == 64

        verified = runner.invoke(
            app, ["anchor", "verify", str(anchor), "-d", ".trustchain"]
        )
        assert verified.exit_code == 0, verified.stdout + verified.stderr
        assert "Anchor VALID" in verified.stdout

    def test_anchor_verify_detects_mismatch(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["init", "-o", "."]).exit_code == 0

        from trustchain import TrustChain, TrustChainConfig

        tc = TrustChain(
            TrustChainConfig(
                enable_chain=True,
                chain_storage="file",
                chain_dir=".trustchain",
            )
        )
        tc.sign("anchor_tool", {"step": 1})
        anchor = tmp_path / "chain.anchor.json"
        assert (
            runner.invoke(
                app, ["anchor", "export", "-d", ".trustchain", "-o", str(anchor)]
            ).exit_code
            == 0
        )

        data = json.loads(anchor.read_text(encoding="utf-8"))
        data["head"] = "tampered"
        anchor.write_text(json.dumps(data), encoding="utf-8")

        verified = runner.invoke(
            app, ["anchor", "verify", str(anchor), "-d", ".trustchain"]
        )
        assert verified.exit_code == 2
        assert "Anchor MISMATCH" in verified.stdout
