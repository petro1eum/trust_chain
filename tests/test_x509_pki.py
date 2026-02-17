"""Tests for X.509 PKI — Real X.509 certificates for AI agents.

Tests cover:
  - Root CA creation (self-signed)
  - Intermediate CA issuance
  - Agent leaf certificate issuance
  - Custom AI OIDs (model_hash, prompt_hash, tool_versions, capabilities)
  - Short-lived certificates
  - Full chain verification (agent → intermediate → root)
  - CRL revocation
  - PEM roundtrip serialization
  - Expired cert detection
  - Wrong CA rejection
  - Agent signing operations
  - CA persistence (save/load)
"""

import time
from datetime import datetime, timedelta, timezone

import pytest

from trustchain.v2.x509_pki import (
    OID_MODEL_HASH,
    OID_PROMPT_HASH,
    AgentCertificate,
    CertVerifyResult,
    TrustChainCA,
)


class TestRootCA:
    """Root Certificate Authority creation."""

    def test_create_root_ca(self):
        """Root CA creates a valid self-signed X.509 certificate."""
        root = TrustChainCA.create_root_ca("Test Root CA")

        assert root.name == "Test Root CA"
        assert root.is_root is True
        assert root.parent is None
        assert root.certificate is not None

        # Self-signed: issuer == subject
        cert = root.certificate
        assert cert.issuer == cert.subject

        # Has CA basic constraint
        bc = cert.extensions.get_extension_for_class(
            __import__("cryptography").x509.BasicConstraints
        )
        assert bc.value.ca is True
        assert bc.value.path_length == 1

    def test_root_ca_pem_export(self):
        """Root CA certificate exports as PEM."""
        root = TrustChainCA.create_root_ca()
        pem = root.certificate_pem

        assert pem.startswith("-----BEGIN CERTIFICATE-----")
        assert pem.strip().endswith("-----END CERTIFICATE-----")

    def test_root_ca_custom_organization(self):
        """Root CA accepts custom organization name."""
        root = TrustChainCA.create_root_ca(
            name="Custom CA",
            organization="Acme Corp",
        )

        from cryptography.x509.oid import NameOID

        org = root.certificate.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )[0].value
        assert org == "Acme Corp"


class TestIntermediateCA:
    """Intermediate CA issuance."""

    def test_issue_intermediate(self):
        """Root CA issues an Intermediate CA certificate."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca("Platform CA")

        assert intermediate.name == "Platform CA"
        assert intermediate.is_root is False
        assert intermediate.parent is root

        # Intermediate cert signed by root
        cert = intermediate.certificate
        assert cert.issuer == root.certificate.subject

    def test_intermediate_is_ca(self):
        """Intermediate certificate has CA=True, path_length=0."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        from cryptography.x509 import BasicConstraints

        bc = intermediate.certificate.extensions.get_extension_for_class(
            BasicConstraints
        )
        assert bc.value.ca is True
        assert bc.value.path_length == 0

    def test_intermediate_verifiable_by_root(self):
        """Intermediate cert is verifiable against Root CA."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        result = root.verify_cert(intermediate.certificate)
        assert result.valid is True
        assert result.errors == []


class TestAgentCertificate:
    """Agent leaf certificate issuance and properties."""

    def test_issue_agent_cert(self):
        """Issue a basic agent certificate."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        agent = intermediate.issue_agent_cert(
            agent_id="procurement-agent-01",
        )

        assert agent.agent_id == "procurement-agent-01"
        assert agent.organization == "TrustChain"
        assert agent.is_valid is True
        assert agent.is_short_lived is True  # 1hr default

    def test_custom_oids(self):
        """Agent cert contains custom AI OIDs (model_hash, prompt_hash)."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        agent = intermediate.issue_agent_cert(
            agent_id="test-agent",
            model_hash="sha256:abcdef1234567890",
            prompt_hash="sha256:fedcba0987654321",
            tool_versions={"bash_tool": "1.0", "web_search": "2.3"},
            capabilities=["read", "write", "execute"],
        )

        assert agent.model_hash == "sha256:abcdef1234567890"
        assert agent.prompt_hash == "sha256:fedcba0987654321"
        assert agent.tool_versions == {"bash_tool": "1.0", "web_search": "2.3"}
        assert agent.capabilities == ["read", "write", "execute"]

    def test_short_lived_default(self):
        """Agent certs are short-lived (1hr) by default."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        agent = intermediate.issue_agent_cert("test")
        validity = agent.not_after - agent.not_before
        assert validity <= timedelta(hours=1, seconds=5)  # Allow small slack
        assert agent.is_short_lived is True

    def test_custom_validity(self):
        """Agent cert supports custom validity period."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        agent = intermediate.issue_agent_cert("long-agent", validity_hours=48)
        assert agent.is_short_lived is False  # 48h > 24h threshold

    def test_agent_not_ca(self):
        """Agent certificate cannot sign other certificates."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("test")

        from cryptography.x509 import BasicConstraints

        bc = agent.certificate.extensions.get_extension_for_class(BasicConstraints)
        assert bc.value.ca is False

    def test_fingerprint(self):
        """Agent cert has a readable fingerprint."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("test")

        fp = agent.fingerprint
        assert len(fp) == 24  # first 24 hex chars of SHA-256
        assert all(c in "0123456789abcdef" for c in fp)

    def test_to_dict(self):
        """to_dict() returns comprehensive agent info."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert(
            "my-agent",
            model_hash="model_abc",
            prompt_hash="prompt_xyz",
        )

        d = agent.to_dict()
        assert d["agent_id"] == "my-agent"
        assert d["model_hash"] == "model_abc"
        assert d["prompt_hash"] == "prompt_xyz"
        assert d["is_valid"] is True
        assert d["is_short_lived"] is True
        assert "not_before" in d
        assert "not_after" in d


class TestChainVerification:
    """Full chain verification: Agent → Intermediate → Root."""

    def test_full_chain(self):
        """Agent cert verifies through the full chain."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("agent-1")

        # Full chain
        assert agent.verify_chain([intermediate, root]) is True

    def test_chain_fails_wrong_root(self):
        """Chain fails if wrong root CA provided."""
        root1 = TrustChainCA.create_root_ca("Root 1")
        root2 = TrustChainCA.create_root_ca("Root 2")
        intermediate = root1.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("agent-1")

        # Wrong root
        assert agent.verify_chain([intermediate, root2]) is False

    def test_chain_fails_wrong_intermediate(self):
        """Agent cert fails verification against wrong intermediate."""
        root = TrustChainCA.create_root_ca()
        int1 = root.issue_intermediate_ca("Int 1")
        int2 = root.issue_intermediate_ca("Int 2")

        agent = int1.issue_agent_cert("agent-1")

        # Wrong intermediate
        assert agent.verify_chain([int2, root]) is False

    def test_verify_against_issuer(self):
        """Agent can verify directly against its issuer."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("agent-1")

        result = agent.verify_against(intermediate)
        assert result.valid is True

    def test_verify_against_wrong_ca(self):
        """Verification fails against non-issuer CA."""
        root1 = TrustChainCA.create_root_ca("Root 1")
        root2 = TrustChainCA.create_root_ca("Root 2")
        int1 = root1.issue_intermediate_ca()
        agent = int1.issue_agent_cert("agent-1")

        result = agent.verify_against(root2)
        assert result.valid is False
        assert "INVALID_SIGNATURE" in result.errors


class TestRevocation:
    """CRL (Certificate Revocation List) — the red button."""

    def test_revoke_agent(self):
        """Revoking agent cert makes verification fail."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("agent-1")

        # Before revocation
        result = agent.verify_against(intermediate)
        assert result.valid is True

        # Revoke
        intermediate.revoke(agent.serial_number, "Prompt injection detected")

        # After revocation
        result = agent.verify_against(intermediate)
        assert result.valid is False
        assert "REVOKED" in result.errors

    def test_crl_contains_revoked(self):
        """CRL lists revoked certificate serial numbers."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("agent-1")

        intermediate.revoke(agent.serial_number, "compromised")

        # CRL should contain the serial
        crl = intermediate.get_crl()
        revoked = list(crl)
        assert len(revoked) == 1
        assert revoked[0].serial_number == agent.serial_number

    def test_crl_pem_format(self):
        """CRL is exportable as PEM."""
        root = TrustChainCA.create_root_ca()
        crl_pem = root.crl_pem

        assert "-----BEGIN X509 CRL-----" in crl_pem
        assert "-----END X509 CRL-----" in crl_pem

    def test_is_revoked(self):
        """is_revoked() check works correctly."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        a1 = intermediate.issue_agent_cert("agent-1")
        a2 = intermediate.issue_agent_cert("agent-2")

        intermediate.revoke(a1.serial_number)

        assert intermediate.is_revoked(a1.serial_number) is True
        assert intermediate.is_revoked(a2.serial_number) is False


class TestPEMSerialization:
    """PEM export/import roundtrip."""

    def test_pem_roundtrip(self):
        """Agent cert survives PEM export/import roundtrip."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert(
            "roundtrip-agent",
            model_hash="model_v1",
            prompt_hash="prompt_v2",
        )

        # Export
        pem = agent.to_pem()
        assert pem.startswith("-----BEGIN CERTIFICATE-----")

        # Import
        restored = AgentCertificate.from_pem(pem)
        assert restored.agent_id == "roundtrip-agent"
        assert restored.model_hash == "model_v1"
        assert restored.prompt_hash == "prompt_v2"
        assert restored.serial_number == agent.serial_number

    def test_pem_preserves_oids(self):
        """Custom OIDs survive PEM roundtrip."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert(
            "oid-test",
            tool_versions={"bash": "1.0", "web": "2.0"},
            capabilities=["read", "write"],
        )

        restored = AgentCertificate.from_pem(agent.to_pem())
        assert restored.tool_versions == {"bash": "1.0", "web": "2.0"}
        assert restored.capabilities == ["read", "write"]


class TestAgentSigning:
    """Agent signs operations using its private key."""

    def test_sign_and_verify(self):
        """Agent can sign data and verify the signature."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("signer-agent")

        data = b"tool:bash_tool|result:ok|ts:2026-02-17"
        signature = agent.sign_data(data)

        assert agent.verify_signature(data, signature) is True

    def test_verify_detects_tampering(self):
        """Tampered data fails signature verification."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("signer-agent")

        data = b"original data"
        signature = agent.sign_data(data)

        assert agent.verify_signature(b"tampered data", signature) is False

    def test_sign_without_key_raises(self):
        """Signing without private key raises ValueError."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("test")

        # Import from PEM loses private key
        no_key = AgentCertificate.from_pem(agent.to_pem())

        with pytest.raises(ValueError, match="No private key"):
            no_key.sign_data(b"data")


class TestExpiration:
    """Certificate expiration handling."""

    def test_expired_cert_detected(self):
        """Expired certificates are correctly detected."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        # Issue cert that's already expired (validity_hours=0 → expires immediately)
        # We'll create a custom cert with past dates
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.x509.oid import NameOID

        key = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)

        cert = (
            cx509.CertificateBuilder()
            .subject_name(
                cx509.Name(
                    [
                        cx509.NameAttribute(NameOID.COMMON_NAME, "expired-agent"),
                    ]
                )
            )
            .issuer_name(intermediate.certificate.subject)
            .public_key(key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(now - timedelta(hours=2))
            .not_valid_after(now - timedelta(hours=1))
            .add_extension(
                cx509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(intermediate._private_key, algorithm=None)
        )

        expired = AgentCertificate(certificate=cert)
        assert expired.is_valid is False

        result = intermediate.verify_cert(cert)
        assert result.valid is False
        assert "EXPIRED" in result.errors

    def test_validity_remaining(self):
        """validity_remaining shows correct time left."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()
        agent = intermediate.issue_agent_cert("test", validity_hours=2)

        remaining = agent.validity_remaining
        assert remaining.total_seconds() > 7000  # ~2 hours minus small delta
        assert remaining.total_seconds() < 7201


class TestCAPersistence:
    """Save/Load CA to disk."""

    def test_save_and_load(self, tmp_path):
        """CA can be saved and loaded from disk."""
        root = TrustChainCA.create_root_ca("Persistent CA")
        root.save(str(tmp_path / "ca"))

        # Files exist
        assert (tmp_path / "ca" / "persistent_ca.crt").exists()
        assert (tmp_path / "ca" / "persistent_ca.key").exists()
        assert (tmp_path / "ca" / "persistent_ca.crl").exists()

        # Reload
        loaded = TrustChainCA.load(str(tmp_path / "ca"), "Persistent CA")
        assert loaded.name == "Persistent CA"
        assert loaded.certificate_pem == root.certificate_pem

    def test_loaded_ca_can_issue(self, tmp_path):
        """Loaded CA can still issue certificates."""
        root = TrustChainCA.create_root_ca("Issuer CA")
        root.save(str(tmp_path / "ca"))

        loaded = TrustChainCA.load(str(tmp_path / "ca"), "Issuer CA")
        intermediate = loaded.issue_intermediate_ca("Child CA")

        result = loaded.verify_cert(intermediate.certificate)
        assert result.valid is True


class TestCertVerifyResult:
    """CertVerifyResult serialization."""

    def test_to_dict(self):
        """Result can be serialized to dict."""
        result = CertVerifyResult(
            valid=True,
            errors=[],
            issuer="Root CA",
            subject="agent-01",
            serial=12345,
            not_after="2026-12-31T00:00:00+00:00",
        )
        d = result.to_dict()
        assert d["valid"] is True
        assert d["subject"] == "agent-01"
        assert d["serial"] == 12345


class TestSubAgentDelegation:
    """B+ (SPIFFE-style) sub-agent delegation.

    Platform CA remains sole issuer. Agents NEVER get CA=TRUE.
    Sub-agents are linked via parent_cert_serial OID.
    Revoking parent cascades to all sub-agents (PARENT_REVOKED).
    """

    def test_sub_agent_has_parent_serial(self):
        """Sub-agent cert contains parent_cert_serial OID."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        parent = intermediate.issue_agent_cert("main-agent")
        child = intermediate.issue_agent_cert(
            "sub-agent-1",
            parent_serial=parent.serial_number,
        )

        assert child.parent_serial == parent.serial_number
        assert child.is_sub_agent is True
        assert parent.is_sub_agent is False
        assert parent.parent_serial is None

    def test_sub_agent_valid_without_parent_revocation(self):
        """Sub-agent verifies OK when parent is not revoked."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        parent = intermediate.issue_agent_cert("main-agent")
        child = intermediate.issue_agent_cert(
            "sub-agent",
            parent_serial=parent.serial_number,
        )

        result = intermediate.verify_cert(child.certificate)
        assert result.valid is True
        assert result.errors == []

    def test_cascading_revocation(self):
        """Revoking parent makes sub-agent fail with PARENT_REVOKED."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        parent = intermediate.issue_agent_cert("main-agent")
        child1 = intermediate.issue_agent_cert(
            "sub-agent-1", parent_serial=parent.serial_number
        )
        child2 = intermediate.issue_agent_cert(
            "sub-agent-2", parent_serial=parent.serial_number
        )

        # Before revocation — all valid
        assert intermediate.verify_cert(parent.certificate).valid is True
        assert intermediate.verify_cert(child1.certificate).valid is True
        assert intermediate.verify_cert(child2.certificate).valid is True

        # Revoke the PARENT only
        intermediate.revoke(parent.serial_number, "Prompt injection")

        # Parent is directly REVOKED
        parent_result = intermediate.verify_cert(parent.certificate)
        assert parent_result.valid is False
        assert "REVOKED" in parent_result.errors

        # Both children fail with PARENT_REVOKED (cascade!)
        child1_result = intermediate.verify_cert(child1.certificate)
        assert child1_result.valid is False
        assert "PARENT_REVOKED" in child1_result.errors

        child2_result = intermediate.verify_cert(child2.certificate)
        assert child2_result.valid is False
        assert "PARENT_REVOKED" in child2_result.errors

    def test_revoke_child_only(self):
        """Revoking one child doesn't affect parent or siblings."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        parent = intermediate.issue_agent_cert("main-agent")
        child1 = intermediate.issue_agent_cert(
            "sub-1", parent_serial=parent.serial_number
        )
        child2 = intermediate.issue_agent_cert(
            "sub-2", parent_serial=parent.serial_number
        )

        # Revoke only child1
        intermediate.revoke(child1.serial_number, "compromised")

        # Parent still valid
        assert intermediate.verify_cert(parent.certificate).valid is True
        # Child1 revoked
        assert intermediate.verify_cert(child1.certificate).valid is False
        # Child2 still valid
        assert intermediate.verify_cert(child2.certificate).valid is True

    def test_sub_agent_not_ca(self):
        """Sub-agents never get CA=TRUE (B+ security)."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        parent = intermediate.issue_agent_cert("main")
        child = intermediate.issue_agent_cert("sub", parent_serial=parent.serial_number)

        from cryptography.x509 import BasicConstraints

        bc = child.certificate.extensions.get_extension_for_class(BasicConstraints)
        assert bc.value.ca is False

    def test_parent_serial_pem_roundtrip(self):
        """Parent serial OID survives PEM export/import."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        parent = intermediate.issue_agent_cert("main")
        child = intermediate.issue_agent_cert("sub", parent_serial=parent.serial_number)

        restored = AgentCertificate.from_pem(child.to_pem())
        assert restored.parent_serial == parent.serial_number
        assert restored.is_sub_agent is True

    def test_to_dict_includes_parent(self):
        """to_dict() includes parent_serial and is_sub_agent."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        parent = intermediate.issue_agent_cert("main")
        child = intermediate.issue_agent_cert("sub", parent_serial=parent.serial_number)

        d = child.to_dict()
        assert d["parent_serial"] == parent.serial_number
        assert d["is_sub_agent"] is True

        pd = parent.to_dict()
        assert pd["parent_serial"] is None
        assert pd["is_sub_agent"] is False

    def test_chain_verify_sub_agent(self):
        """Sub-agent verifies through full chain."""
        root = TrustChainCA.create_root_ca()
        intermediate = root.issue_intermediate_ca()

        parent = intermediate.issue_agent_cert("main")
        child = intermediate.issue_agent_cert("sub", parent_serial=parent.serial_number)

        # Sub-agent chain: same as any agent (Platform CA → Root)
        assert child.verify_chain([intermediate, root]) is True

    def test_spawn_sub_agent_via_trustchain(self, tmp_path):
        """TrustChain.spawn_sub_agent() creates B+ linked sub-agent."""
        from trustchain.v2 import TrustChain, TrustChainConfig

        config = TrustChainConfig(
            chain_dir=str(tmp_path / ".trustchain"),
            enable_pki=True,
            pki_agent_id="main-orchestrator",
        )
        tc = TrustChain(config)

        # Main agent exists
        assert tc.agent_cert is not None
        assert tc.agent_cert.agent_id == "main-orchestrator"

        # Spawn sub-agent
        sub = tc.spawn_sub_agent(
            agent_id="price-comparator",
            model_hash="sha256:model_v2",
            capabilities=["read", "search"],
        )

        assert sub.agent_id == "price-comparator"
        assert sub.is_sub_agent is True
        assert sub.parent_serial == tc.agent_cert.serial_number
        assert sub.model_hash == "sha256:model_v2"

        # Sub-agent verifies through full chain
        assert sub.verify_chain([tc.pki_intermediate_ca, tc.pki_root_ca]) is True

        # Revoke main agent → sub-agent becomes invalid
        tc.revoke_agent(tc.agent_cert, "test revocation")
        result = sub.verify_against(tc.pki_intermediate_ca)
        assert result.valid is False
        assert "PARENT_REVOKED" in result.errors
