"""Tests for all example files.

These tests ensure that all examples in the examples/ directory work correctly.
This prevents the situation where library tests pass but examples fail in CI.
"""

import pytest
import subprocess
import sys
import os
from pathlib import Path

# Get the project root
PROJECT_ROOT = Path(__file__).parent.parent


def run_example(example_name: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run an example script and return the result."""
    example_path = PROJECT_ROOT / "examples" / example_name

    result = subprocess.run(
        [sys.executable, str(example_path)],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=PROJECT_ROOT,
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
    )

    return result


class TestExamplesRun:
    """Test that all examples run without errors."""

    def test_secure_rag_example(self):
        """Test secure_rag.py runs successfully."""
        result = run_example("secure_rag.py")

        assert result.returncode == 0, f"secure_rag.py failed:\n{result.stderr}"
        assert "Merkle" in result.stdout or "merkle" in result.stdout.lower()

    def test_database_agent_example(self):
        """Test database_agent.py runs successfully."""
        result = run_example("database_agent.py")

        assert result.returncode == 0, f"database_agent.py failed:\n{result.stderr}"
        assert "Chain" in result.stdout or "chain" in result.stdout.lower()

    def test_api_agent_example(self):
        """Test api_agent.py runs successfully."""
        result = run_example("api_agent.py")

        assert result.returncode == 0, f"api_agent.py failed:\n{result.stderr}"
        assert "CloudEvents" in result.stdout or "event" in result.stdout.lower()

    def test_langchain_agent_example(self):
        """Test langchain_agent.py runs successfully."""
        result = run_example("langchain_agent.py")

        # This may have warnings but should not fail
        assert result.returncode == 0, f"langchain_agent.py failed:\n{result.stderr}"

    def test_mcp_claude_desktop_example(self):
        """Test mcp_claude_desktop.py can be imported (not run as it starts server)."""
        # This example starts a server, so we just import it
        import_result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, '.'); exec(open('examples/mcp_claude_desktop.py').read().split('if __name__')[0])",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=PROJECT_ROOT,
        )

        # Import should work
        assert (
            import_result.returncode == 0
        ), f"mcp_claude_desktop.py import failed:\n{import_result.stderr}"

    def test_full_enforcement_demo(self):
        """Test full_enforcement_demo.py runs successfully."""
        result = run_example("full_enforcement_demo.py", timeout=60)

        assert (
            result.returncode == 0
        ), f"full_enforcement_demo.py failed:\n{result.stderr}"
        assert "Enforcement" in result.stdout or "enforcement" in result.stdout.lower()


class TestExamplesOutput:
    """Test that examples produce expected output."""

    def test_secure_rag_verifies_chunks(self):
        """Test that secure_rag.py actually verifies chunks."""
        result = run_example("secure_rag.py")

        # Should mention verification
        assert "verif" in result.stdout.lower(), "secure_rag.py should verify chunks"

    def test_database_agent_chain_verified(self):
        """Test that database_agent.py verifies its chain."""
        result = run_example("database_agent.py")

        # Should show chain is verified
        assert "True" in result.stdout or "verified" in result.stdout.lower()

    def test_api_agent_generates_events(self):
        """Test that api_agent.py generates CloudEvents."""
        result = run_example("api_agent.py")

        # Should mention events
        assert "event" in result.stdout.lower()

    def test_full_enforcement_detects_tampering(self):
        """Test that full_enforcement_demo.py detects tampering."""
        result = run_example("full_enforcement_demo.py", timeout=60)

        # Should show tampering was detected (False for tampered verification)
        assert "False" in result.stdout or "tamper" in result.stdout.lower()


class TestExamplesNoRegressions:
    """Regression tests for specific bugs we've fixed."""

    def test_no_nonce_replay_in_verification_demo(self):
        """
        Regression test for: NonceReplayError in full_enforcement_demo.py

        Bug: Calling tc.verify() twice on same response caused NonceReplayError
        Fix: Use _signer.verify() for tampered check to avoid nonce consumption
        """
        result = run_example("full_enforcement_demo.py", timeout=60)

        assert (
            result.returncode == 0
        ), f"Nonce replay regression! Error:\n{result.stderr}"
        assert (
            "NonceReplayError" not in result.stderr
        ), "NonceReplayError should not occur"
