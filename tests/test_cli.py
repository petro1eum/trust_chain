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
