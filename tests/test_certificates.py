"""Tests for Tool Certificates / PKI system."""

import shutil
import tempfile
from pathlib import Path

import pytest

from trustchain.v2.certificate import (
    ToolCertificate,
    ToolRegistry,
    UntrustedToolError,
    compute_code_hash,
    trustchain_certified,
)


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="tc_cert_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ── Test functions (tools to certify) ──


def sample_tool(query: str) -> dict:
    """A safe, certified tool."""
    return {"result": f"processed: {query}"}


def another_tool(data: dict) -> dict:
    """Another tool for testing."""
    return {"output": data}


class TestComputeCodeHash:
    def test_hash_is_deterministic(self):
        h1 = compute_code_hash(sample_tool)
        h2 = compute_code_hash(sample_tool)
        assert h1 == h2

    def test_different_functions_different_hashes(self):
        h1 = compute_code_hash(sample_tool)
        h2 = compute_code_hash(another_tool)
        assert h1 != h2

    def test_hash_is_sha256(self):
        h = compute_code_hash(sample_tool)
        assert len(h) == 64  # SHA-256 hex digest


class TestToolCertificate:
    def test_create_certificate(self):
        cert = ToolCertificate(
            tool_name="sample_tool",
            tool_module="tests.test_certificates",
            code_hash="abc123",
            issuer="self-signed",
        )
        assert cert.tool_name == "sample_tool"
        assert cert.is_valid is True
        assert cert.revoked is False

    def test_revoked_certificate_invalid(self):
        cert = ToolCertificate(
            tool_name="bad_tool",
            tool_module="evil",
            revoked=True,
        )
        assert cert.is_valid is False

    def test_expired_certificate_invalid(self):
        cert = ToolCertificate(
            tool_name="old_tool",
            tool_module="legacy",
            expires_at="2020-01-01T00:00:00+00:00",
        )
        assert cert.is_valid is False

    def test_to_dict_and_from_dict(self):
        cert = ToolCertificate(
            tool_name="test",
            tool_module="mod",
            code_hash="hash123",
            owner="Alice",
        )
        d = cert.to_dict()
        cert2 = ToolCertificate.from_dict(d)
        assert cert2.tool_name == "test"
        assert cert2.owner == "Alice"
        assert cert2.code_hash == "hash123"

    def test_fingerprint(self):
        cert = ToolCertificate(
            tool_name="t",
            tool_module="m",
            code_hash="a" * 64,
        )
        assert cert.fingerprint == "aaaaaaaaaaaa..."


class TestToolRegistry:
    def test_certify_and_verify(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        registry.certify(sample_tool, owner="Dev Team")

        assert registry.verify(sample_tool) is True

    def test_uncertified_tool_fails(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        # Don't certify another_tool
        assert registry.verify(another_tool) is False

    def test_violation_recorded(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        registry.verify(another_tool)

        assert len(registry.violations) == 1
        assert registry.violations[0]["type"] == "NO_CERTIFICATE"

    def test_revoke_certificate(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        registry.certify(sample_tool)
        assert registry.verify(sample_tool) is True

        registry.revoke(sample_tool, reason="Security vulnerability")
        assert registry.verify(sample_tool) is False

    def test_certificate_persists_to_disk(self, tmp_dir):
        registry1 = ToolRegistry(registry_dir=tmp_dir)
        registry1.certify(sample_tool, owner="Team A")

        # New registry should load from disk
        registry2 = ToolRegistry(registry_dir=tmp_dir)
        cert = registry2.get_cert(sample_tool)
        assert cert is not None
        assert cert.owner == "Team A"

    def test_list_certs(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        registry.certify(sample_tool)
        registry.certify(another_tool)

        certs = registry.list_certs()
        assert len(certs) == 2

    def test_get_cert(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        registry.certify(sample_tool, organization="Acme Corp")

        cert = registry.get_cert(sample_tool)
        assert cert is not None
        assert cert.organization == "Acme Corp"
        assert cert.code_hash == compute_code_hash(sample_tool)

    def test_certify_with_signer(self, tmp_dir):
        """Test certificate signing with a real Signer."""
        from trustchain.v2.signer import Signer

        signer = Signer()

        registry = ToolRegistry(registry_dir=tmp_dir, signer=signer)
        cert = registry.certify(sample_tool)

        assert cert.signature != ""
        assert cert.issuer_key_id != ""
        assert cert.trust_level == "internal"
        assert cert.issuer == "internal-ca"


class TestTrustchainCertifiedDecorator:
    def test_certified_tool_executes(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        registry.certify(sample_tool)

        # Apply decorator to the SAME function (not a redefinition)
        wrapped = trustchain_certified(registry)(sample_tool)
        result = wrapped("test")
        assert result == {"result": "processed: test"}

    def test_uncertified_tool_raises(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        # NOT certified

        @trustchain_certified(registry, strict=True)
        def dangerous_tool(cmd: str) -> dict:
            return {"executed": cmd}

        with pytest.raises(UntrustedToolError) as exc_info:
            dangerous_tool("rm -rf /")

        assert "DENY" in str(exc_info.value)
        assert "dangerous_tool" in str(exc_info.value)

    def test_non_strict_allows_execution(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)

        @trustchain_certified(registry, strict=False)
        def risky_tool() -> str:
            return "executed anyway"

        # Non-strict mode: logs violation but allows execution
        result = risky_tool()
        assert result == "executed anyway"
        assert len(registry.violations) > 0

    def test_wrapper_preserves_metadata(self, tmp_dir):
        registry = ToolRegistry(registry_dir=tmp_dir)
        registry.certify(sample_tool)

        wrapped = trustchain_certified(registry)(sample_tool)
        assert wrapped.__name__ == "sample_tool"
        assert wrapped._trustchain_certified is True


class TestCodeTamperingDetection:
    """The critical security test: detect code modification."""

    def test_detect_tampered_code(self, tmp_dir):
        """If tool code changes after certification, verification MUST fail."""
        registry = ToolRegistry(registry_dir=tmp_dir)

        # Certify the original
        def my_tool(x):
            return x + 1

        registry.certify(my_tool)
        assert registry.verify(my_tool) is True

        # "Tamper" with the code by creating a new function with same name
        # (simulates an attacker modifying the tool)
        def my_tool(x):
            return x + 1000  # MALICIOUS CHANGE

        # Verification should FAIL because code hash changed
        assert registry.verify(my_tool) is False

        # Check violation was recorded
        violations = registry.violations
        tamper_violations = [v for v in violations if v["type"] == "CODE_TAMPERED"]
        assert len(tamper_violations) == 1
        assert "hash mismatch" in tamper_violations[0]["detail"]
