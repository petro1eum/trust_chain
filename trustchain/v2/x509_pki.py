"""X.509 PKI for AI Agents — Enterprise Identity Infrastructure.

Real X.509 certificates for AI agents using the `cryptography` library.
Follows the SSL/TLS CA hierarchy model adapted for autonomous agents.

Architecture:
    Root CA (CISO)
      └── Intermediate CA (TrustChain Platform)
            ├── Agent Cert (agent-procurement-01)  — 1hr validity
            ├── Agent Cert (agent-analytics-02)    — 1hr validity
            └── Agent Cert (agent-compliance-03)   — 1hr validity

Custom X.509 OIDs for AI-specific metadata:
    1.3.6.1.4.1.99999.1 — model_hash (SHA-256 of model weights/version)
    1.3.6.1.4.1.99999.2 — prompt_hash (SHA-256 of system prompt)
    1.3.6.1.4.1.99999.3 — tool_versions (JSON of registered tool versions)
    1.3.6.1.4.1.99999.4 — agent_capabilities (JSON capabilities list)

Usage:
    # 1. Create Root CA (CISO does this once)
    root = TrustChainCA.create_root_ca("TrustChain Root CA")

    # 2. Create Intermediate CA (platform-level)
    intermediate = root.issue_intermediate_ca("TrustChain Platform CA")

    # 3. Issue short-lived agent cert
    agent_cert = intermediate.issue_agent_cert(
        agent_id="procurement-agent-01",
        model_hash="sha256:abc123...",
        prompt_hash="sha256:def456...",
        validity_hours=1,
    )

    # 4. Verify the full chain
    assert agent_cert.verify_chain([intermediate, root])

    # 5. Revoke if compromised
    intermediate.revoke(agent_cert.serial_number, "Prompt injection detected")
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

# ── Custom OIDs for AI Agent metadata ──
# Using Private Enterprise Number (PEN) space: 1.3.6.1.4.1.99999.x
# In production, register a real PEN with IANA.

AI_OID_BASE = "1.3.6.1.4.1.99999"
OID_MODEL_HASH = x509.ObjectIdentifier(f"{AI_OID_BASE}.1")
OID_PROMPT_HASH = x509.ObjectIdentifier(f"{AI_OID_BASE}.2")
OID_TOOL_VERSIONS = x509.ObjectIdentifier(f"{AI_OID_BASE}.3")
OID_AGENT_CAPABILITIES = x509.ObjectIdentifier(f"{AI_OID_BASE}.4")
OID_PARENT_AGENT_SERIAL = x509.ObjectIdentifier(f"{AI_OID_BASE}.5")


class TrustChainCA:
    """X.509 Certificate Authority for AI Agents.

    Supports three roles:
    - Root CA: self-signed, long validity (10 years default)
    - Intermediate CA: signed by Root, medium validity (1 year)
    - Leaf issuer: issues short-lived agent certificates
    """

    def __init__(
        self,
        name: str,
        private_key: Ed25519PrivateKey,
        certificate: x509.Certificate,
        parent: Optional["TrustChainCA"] = None,
    ):
        self._name = name
        self._private_key = private_key
        self._certificate = certificate
        self._parent = parent
        self._revoked: Dict[int, Tuple[datetime, str]] = {}  # serial -> (time, reason)
        self._issued_serials: List[int] = []
        self._next_serial = 1000

    # ── Factory methods ──

    @classmethod
    def create_root_ca(
        cls,
        name: str = "TrustChain Root CA",
        organization: str = "TrustChain",
        validity_days: int = 3650,
    ) -> "TrustChainCA":
        """Create a self-signed Root Certificate Authority.

        The Root CA is the absolute source of trust.
        Typically created once by the CISO and stored securely.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AI Security"),
            ]
        )

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .sign(private_key, algorithm=None)  # Ed25519 doesn't need hash
        )

        return cls(name=name, private_key=private_key, certificate=cert)

    def issue_intermediate_ca(
        self,
        name: str = "TrustChain Platform CA",
        organization: str = "TrustChain",
        validity_days: int = 365,
    ) -> "TrustChainCA":
        """Issue an Intermediate CA certificate, signed by this CA.

        The Intermediate CA issues agent certificates. This limits
        exposure of the Root CA private key.
        """
        int_key = Ed25519PrivateKey.generate()
        int_public = int_key.public_key()

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AI Platform"),
            ]
        )

        now = datetime.now(timezone.utc)
        serial = self._next_serial_number()

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(int_public)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(int_public),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._certificate.public_key()
                ),
                critical=False,
            )
            .sign(self._private_key, algorithm=None)
        )

        return TrustChainCA(
            name=name,
            private_key=int_key,
            certificate=cert,
            parent=self,
        )

    def issue_agent_cert(
        self,
        agent_id: str,
        model_hash: str = "",
        prompt_hash: str = "",
        tool_versions: Optional[Dict[str, str]] = None,
        capabilities: Optional[List[str]] = None,
        validity_hours: int = 1,
        organization: str = "TrustChain",
        parent_serial: Optional[int] = None,
    ) -> "AgentCertificate":
        """Issue a short-lived X.509 certificate for an AI agent.

        Agent certificates are leaf certs — they cannot sign other certs.
        Default validity is 1 hour (short-lived for security).

        B+ Pattern (SPIFFE-style): If parent_serial is provided, this
        creates a sub-agent cert linked to its parent. The Platform CA
        remains the sole issuer — agents NEVER get CA=TRUE. Cascading
        revocation works by checking parent's CRL status during verify.

        Custom OIDs embed AI-specific metadata directly in the cert:
        - model_hash: SHA-256 of model weights/version
        - prompt_hash: SHA-256 of system prompt
        - tool_versions: registered tool versions
        - capabilities: what this agent is allowed to do
        - parent_cert_serial: serial of parent agent (for sub-agents)

        Args:
            agent_id: Unique agent identifier (becomes CN)
            model_hash: Hash of the AI model
            prompt_hash: Hash of the system prompt
            tool_versions: Dict of tool_name -> version
            capabilities: List of capabilities
            validity_hours: How long cert is valid (default 1hr)
            organization: Organization name
            parent_serial: Serial number of parent agent cert (sub-agent)

        Returns:
            AgentCertificate wrapping the X.509 cert
        """
        agent_key = Ed25519PrivateKey.generate()
        agent_public = agent_key.public_key()

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AI Agent"),
            ]
        )

        now = datetime.now(timezone.utc)
        serial = self._next_serial_number()
        validity = timedelta(hours=validity_hours)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(agent_public)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + validity)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(agent_public),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._certificate.public_key()
                ),
                critical=False,
            )
        )

        # Add custom AI OIDs as extensions
        if model_hash:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    OID_MODEL_HASH,
                    model_hash.encode("utf-8"),
                ),
                critical=False,
            )

        if prompt_hash:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    OID_PROMPT_HASH,
                    prompt_hash.encode("utf-8"),
                ),
                critical=False,
            )

        if tool_versions:
            tv_json = json.dumps(tool_versions, sort_keys=True).encode("utf-8")
            builder = builder.add_extension(
                x509.UnrecognizedExtension(OID_TOOL_VERSIONS, tv_json),
                critical=False,
            )

        if capabilities:
            cap_json = json.dumps(capabilities, sort_keys=True).encode("utf-8")
            builder = builder.add_extension(
                x509.UnrecognizedExtension(OID_AGENT_CAPABILITIES, cap_json),
                critical=False,
            )

        if parent_serial is not None:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    OID_PARENT_AGENT_SERIAL,
                    str(parent_serial).encode("utf-8"),
                ),
                critical=False,
            )

        cert = builder.sign(self._private_key, algorithm=None)

        return AgentCertificate(
            certificate=cert,
            private_key=agent_key,
            issuer_ca=self,
            serial=serial,
        )

    # ── Revocation ──

    def revoke(self, serial_number: int, reason: str = "unspecified") -> None:
        """Revoke a certificate by serial number.

        Once revoked, the certificate will fail verification via CRL.
        This is the "red button" — instant agent termination.
        """
        self._revoked[serial_number] = (
            datetime.now(timezone.utc),
            reason,
        )

    def is_revoked(self, serial_number: int) -> bool:
        """Check if a serial number is in the revocation list."""
        return serial_number in self._revoked

    def get_crl(self) -> x509.CertificateRevocationList:
        """Generate a Certificate Revocation List (CRL).

        Published periodically so relying parties can check
        whether a certificate has been revoked.
        """
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._certificate.subject)
            .last_update(now)
            .next_update(now + timedelta(hours=1))
        )

        for serial, (revoked_at, _reason) in self._revoked.items():
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revoked_at)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        return builder.sign(self._private_key, algorithm=None)

    @property
    def crl_pem(self) -> str:
        """PEM-encoded CRL for distribution."""
        crl = self.get_crl()
        return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # ── Verification ──

    def verify_cert(self, cert: x509.Certificate) -> "CertVerifyResult":
        """Verify a certificate was issued by this CA.

        Checks:
        1. Signature is valid (signed by this CA's key)
        2. Certificate is not expired
        3. Certificate is not revoked (by serial number)
        4. B+ cascading: if cert has parent_cert_serial OID,
           verify that the parent is NOT revoked either
        """
        errors = []

        # 1. Signature verification
        try:
            self._certificate.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
            )
        except Exception:
            errors.append("INVALID_SIGNATURE")

        # 2. Expiration check
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            errors.append("NOT_YET_VALID")
        if now > cert.not_valid_after_utc:
            errors.append("EXPIRED")

        # 3. Revocation check (direct)
        if self.is_revoked(cert.serial_number):
            errors.append("REVOKED")

        # 4. B+ cascading revocation: check parent agent
        try:
            parent_ext = cert.extensions.get_extension_for_oid(OID_PARENT_AGENT_SERIAL)
            parent_serial = int(parent_ext.value.value.decode("utf-8"))
            if self.is_revoked(parent_serial):
                errors.append("PARENT_REVOKED")
        except x509.ExtensionNotFound:
            pass  # Not a sub-agent, no parent to check

        return CertVerifyResult(
            valid=len(errors) == 0,
            errors=errors,
            issuer=self._name,
            subject=cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            serial=cert.serial_number,
            not_after=cert.not_valid_after_utc.isoformat(),
        )

    # ── Properties ──

    @property
    def name(self) -> str:
        return self._name

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def certificate_pem(self) -> str:
        return self._certificate.public_bytes(serialization.Encoding.PEM).decode(
            "utf-8"
        )

    @property
    def parent(self) -> Optional["TrustChainCA"]:
        return self._parent

    @property
    def is_root(self) -> bool:
        return self._parent is None

    @property
    def revoked_serials(self) -> List[int]:
        return list(self._revoked.keys())

    # ── Persistence ──

    def save(self, directory: str) -> None:
        """Save CA certificate and key to directory."""
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)

        # Save certificate (public)
        cert_path = path / f"{self._safe_name}.crt"
        cert_path.write_bytes(
            self._certificate.public_bytes(serialization.Encoding.PEM)
        )

        # Save private key (sensitive!)
        key_path = path / f"{self._safe_name}.key"
        key_path.write_bytes(
            self._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        # Save CRL
        crl_path = path / f"{self._safe_name}.crl"
        crl_path.write_text(self.crl_pem, encoding="utf-8")

    @classmethod
    def load(cls, directory: str, name: str) -> "TrustChainCA":
        """Load CA from persisted certificate and key files."""
        path = Path(directory)
        safe = name.lower().replace(" ", "_")

        cert_data = (path / f"{safe}.crt").read_bytes()
        key_data = (path / f"{safe}.key").read_bytes()

        certificate = x509.load_pem_x509_certificate(cert_data)
        private_key = serialization.load_pem_private_key(key_data, password=None)

        return cls(
            name=name,
            private_key=private_key,
            certificate=certificate,
        )

    # ── Internal ──

    def _next_serial_number(self) -> int:
        self._next_serial += 1
        self._issued_serials.append(self._next_serial)
        return self._next_serial

    @property
    def _safe_name(self) -> str:
        return self._name.lower().replace(" ", "_")


@dataclass
class CertVerifyResult:
    """Result of certificate verification."""

    valid: bool
    errors: List[str]
    issuer: str
    subject: str
    serial: int
    not_after: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "issuer": self.issuer,
            "subject": self.subject,
            "serial": self.serial,
            "not_after": self.not_after,
        }


class AgentCertificate:
    """X.509 certificate wrapper for an AI agent.

    Provides convenient accessors for AI-specific OIDs
    and standard X.509 fields.
    """

    def __init__(
        self,
        certificate: x509.Certificate,
        private_key: Optional[Ed25519PrivateKey] = None,
        issuer_ca: Optional[TrustChainCA] = None,
        serial: Optional[int] = None,
    ):
        self._certificate = certificate
        self._private_key = private_key
        self._issuer_ca = issuer_ca
        self._serial = serial or certificate.serial_number

    # ── Identity ──

    @property
    def agent_id(self) -> str:
        """Agent identifier (CN from subject)."""
        attrs = self._certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""

    @property
    def organization(self) -> str:
        attrs = self._certificate.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        return attrs[0].value if attrs else ""

    @property
    def serial_number(self) -> int:
        return self._certificate.serial_number

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the certificate (for display)."""
        digest = self._certificate.fingerprint(hashes.SHA256())
        return digest.hex()[:24]

    # ── AI-specific OIDs ──

    @property
    def model_hash(self) -> str:
        """SHA-256 hash of the AI model (from custom OID)."""
        return self._get_custom_oid_str(OID_MODEL_HASH)

    @property
    def prompt_hash(self) -> str:
        """SHA-256 hash of the system prompt (from custom OID)."""
        return self._get_custom_oid_str(OID_PROMPT_HASH)

    @property
    def tool_versions(self) -> Dict[str, str]:
        """Tool versions dict (from custom OID)."""
        raw = self._get_custom_oid_bytes(OID_TOOL_VERSIONS)
        if raw:
            return json.loads(raw.decode("utf-8"))
        return {}

    @property
    def capabilities(self) -> List[str]:
        """Agent capabilities list (from custom OID)."""
        raw = self._get_custom_oid_bytes(OID_AGENT_CAPABILITIES)
        if raw:
            return json.loads(raw.decode("utf-8"))
        return []

    @property
    def parent_serial(self) -> Optional[int]:
        """Serial number of parent agent (None if top-level).

        B+ pattern: sub-agents have their parent's serial embedded
        via OID_PARENT_AGENT_SERIAL. The Platform CA checks this
        during verification for cascading revocation.
        """
        raw = self._get_custom_oid_bytes(OID_PARENT_AGENT_SERIAL)
        if raw:
            return int(raw.decode("utf-8"))
        return None

    @property
    def is_sub_agent(self) -> bool:
        """True if this agent was spawned by another agent."""
        return self.parent_serial is not None

    # ── Validity ──

    @property
    def is_valid(self) -> bool:
        """Check if certificate is currently valid (time-wise)."""
        now = datetime.now(timezone.utc)
        return (
            self._certificate.not_valid_before_utc
            <= now
            <= self._certificate.not_valid_after_utc
        )

    @property
    def is_short_lived(self) -> bool:
        """True if validity period is less than 24 hours."""
        delta = (
            self._certificate.not_valid_after_utc
            - self._certificate.not_valid_before_utc
        )
        return delta < timedelta(hours=24)

    @property
    def not_before(self) -> datetime:
        return self._certificate.not_valid_before_utc

    @property
    def not_after(self) -> datetime:
        return self._certificate.not_valid_after_utc

    @property
    def validity_remaining(self) -> timedelta:
        """Time remaining until expiration."""
        return self._certificate.not_valid_after_utc - datetime.now(timezone.utc)

    # ── Verification ──

    def verify_against(self, ca: TrustChainCA) -> CertVerifyResult:
        """Verify this certificate against a specific CA."""
        return ca.verify_cert(self._certificate)

    def verify_chain(self, chain: List[TrustChainCA]) -> bool:
        """Verify full certificate chain: self → intermediate → root.

        Args:
            chain: List of CAs from issuer to root (in order).

        Returns:
            True if entire chain is valid.
        """
        if not chain:
            return False

        # Verify leaf against first CA
        result = chain[0].verify_cert(self._certificate)
        if not result.valid:
            return False

        # Verify each CA against the next
        for i in range(len(chain) - 1):
            result = chain[i + 1].verify_cert(chain[i].certificate)
            if not result.valid:
                return False

        # Last CA should be self-signed (root)
        last = chain[-1]
        try:
            last.certificate.public_key().verify(
                last.certificate.signature,
                last.certificate.tbs_certificate_bytes,
            )
        except Exception:
            return False

        return True

    # ── Signing (agent signs operations) ──

    def sign_data(self, data: bytes) -> bytes:
        """Sign data using the agent's private key."""
        if not self._private_key:
            raise ValueError("No private key — cannot sign")
        return self._private_key.sign(data)

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature against this agent's public key."""
        try:
            self._certificate.public_key().verify(signature, data)
            return True
        except Exception:
            return False

    # ── Serialization ──

    def to_pem(self) -> str:
        """Export certificate as PEM string."""
        return self._certificate.public_bytes(serialization.Encoding.PEM).decode(
            "utf-8"
        )

    @classmethod
    def from_pem(cls, pem: str) -> "AgentCertificate":
        """Import certificate from PEM string."""
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        return cls(certificate=cert)

    def to_dict(self) -> Dict[str, Any]:
        """Summary dict for display/logging."""
        return {
            "agent_id": self.agent_id,
            "organization": self.organization,
            "serial": self.serial_number,
            "fingerprint": self.fingerprint,
            "model_hash": self.model_hash,
            "prompt_hash": self.prompt_hash,
            "tool_versions": self.tool_versions,
            "capabilities": self.capabilities,
            "parent_serial": self.parent_serial,
            "is_sub_agent": self.is_sub_agent,
            "is_valid": self.is_valid,
            "is_short_lived": self.is_short_lived,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
        }

    @property
    def certificate(self) -> x509.Certificate:
        """Raw X.509 certificate object."""
        return self._certificate

    # ── Internal ──

    def _get_custom_oid_bytes(self, oid: x509.ObjectIdentifier) -> Optional[bytes]:
        """Extract raw bytes from a custom OID extension."""
        try:
            ext = self._certificate.extensions.get_extension_for_oid(oid)
            return ext.value.value
        except x509.ExtensionNotFound:
            return None

    def _get_custom_oid_str(self, oid: x509.ObjectIdentifier) -> str:
        """Extract string value from a custom OID extension."""
        raw = self._get_custom_oid_bytes(oid)
        return raw.decode("utf-8") if raw else ""

    def __repr__(self) -> str:
        return (
            f"AgentCertificate(agent_id='{self.agent_id}', "
            f"serial={self.serial_number}, "
            f"valid={self.is_valid})"
        )
