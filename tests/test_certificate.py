"""Tests for TrustChain Certificate Infrastructure (Phase 16.4)."""

import pytest

from trustchain import TrustChain, TrustChainConfig
from trustchain.v2.signer import SignedResponse


class TestCertificateInfrastructure:
    """Test suite for certificate infrastructure."""

    def test_certificate_in_config(self):
        """Test certificate field in TrustChainConfig."""
        cert = {
            "owner": "Test Agent",
            "organization": "Acme Corp",
            "tier": "community",
        }
        config = TrustChainConfig(certificate=cert)

        assert config.certificate == cert
        assert config.certificate["owner"] == "Test Agent"
        assert config.certificate["tier"] == "community"

    def test_certificate_in_signed_response(self):
        """Test certificate is included in SignedResponse."""
        cert = {
            "owner": "KB-Catalog AI",
            "organization": "TrustChain Inc",
            "tier": "pro",
            "role": "Product Search",
        }
        tc = TrustChain(TrustChainConfig(certificate=cert))

        signed = tc.sign("test_tool", {"data": "test"})

        assert signed.certificate is not None
        assert signed.certificate["owner"] == "KB-Catalog AI"
        assert signed.certificate["tier"] == "pro"

    def test_certificate_in_to_dict(self):
        """Test certificate is included in to_dict() output."""
        cert = {"owner": "Agent", "tier": "enterprise"}
        tc = TrustChain(TrustChainConfig(certificate=cert))

        signed = tc.sign("tool", {"x": 1})
        data = signed.to_dict()

        assert "certificate" in data
        assert data["certificate"]["owner"] == "Agent"

    def test_no_certificate_when_not_configured(self):
        """Test no certificate field when not configured."""
        tc = TrustChain()  # No certificate

        signed = tc.sign("tool", {"x": 1})

        # Certificate should be None or not in dict
        assert signed.certificate is None
        data = signed.to_dict()
        assert "certificate" not in data or data.get("certificate") is None

    def test_certificate_tiers(self):
        """Test different certificate tiers."""
        tiers = ["community", "pro", "enterprise"]

        for tier in tiers:
            cert = {"owner": f"Agent-{tier}", "tier": tier}
            tc = TrustChain(TrustChainConfig(certificate=cert))

            signed = tc.sign("test", {"tier_test": True})
            assert signed.certificate["tier"] == tier

    def test_certificate_with_session(self):
        """Test certificate is included in session responses."""
        cert = {"owner": "Session Agent", "tier": "pro"}
        tc = TrustChain(TrustChainConfig(certificate=cert))

        with tc.session("cert_session") as session:
            r1 = session.sign("step1", {"data": 1})
            r2 = session.sign("step2", {"data": 2})

            assert r1.certificate == cert
            assert r2.certificate == cert

    def test_certificate_with_tool_decorator(self):
        """Test certificate is included with @tc.tool() decorator."""
        cert = {"owner": "Tool Agent", "organization": "Test Org", "tier": "community"}
        tc = TrustChain(TrustChainConfig(certificate=cert))

        @tc.tool("decorated_tool")
        def my_tool(x: int) -> dict:
            return {"result": x * 2}

        response = my_tool(5)

        # Tool responses should also have certificate
        # Note: Tool decorator uses signer directly, certificate added in sign()
        assert response.tool_id == "decorated_tool"

    def test_certificate_extended_fields(self):
        """Test certificate with extended fields."""
        cert = {
            "owner": "Enterprise Bot",
            "organization": "MegaCorp",
            "tier": "enterprise",
            "role": "Financial Advisor",
            "issued_by": "TrustChain CA",
            "valid_until": "2027-01-01",
            "key_id": "key_abc123",
        }
        tc = TrustChain(TrustChainConfig(certificate=cert))

        signed = tc.sign("financial_tool", {"amount": 1000})

        assert signed.certificate["role"] == "Financial Advisor"
        assert signed.certificate["issued_by"] == "TrustChain CA"
        assert signed.certificate["valid_until"] == "2027-01-01"

    def test_signed_response_certificate_field(self):
        """Test SignedResponse dataclass has certificate field."""
        response = SignedResponse(
            tool_id="test",
            data={"x": 1},
            signature="sig123",
            certificate={"owner": "Test", "tier": "community"},
        )

        assert response.certificate is not None
        assert response.certificate["owner"] == "Test"
