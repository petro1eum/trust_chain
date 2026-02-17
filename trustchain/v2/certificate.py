"""Tool Certificates — PKI for AI Agent Tools.

SSL-like certificate system for AI tools. Every tool must present
a valid certificate before execution. Certificates contain a hash
of the tool's source code, signed by a trusted authority (CA).

Architecture follows the SSL/TLS model:

    Tool Author → signs code hash → Tool Certificate
    CISO/Admin → manages → Tool Registry (trusted certs)
    Agent Runtime → checks → Certificate before tool execution

Three trust levels:
    - Self-signed (OSS): developer signs their own tools for testing
    - Internal CA (Pro): company-wide private certificate authority
    - External CA (Enterprise): HSM-backed, auditable root of trust

Usage:
    # 1. Register a tool with automatic code hash
    registry = ToolRegistry()
    registry.certify(my_tool_func)

    # 2. Verify before execution
    if not registry.verify(my_tool_func):
        raise UntrustedToolError(...)

    # 3. Or use the decorator
    @trustchain_certified(registry)
    def my_tool(query: str) -> dict:
        return {"result": "safe"}
"""

import functools
import hashlib
import inspect
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .signer import Signer


@dataclass
class ToolCertificate:
    """Certificate for a trusted AI tool — the 'SSL cert' for tools."""

    # Identity
    tool_name: str
    tool_module: str
    version: str = "1.0.0"

    # Code integrity
    code_hash: str = ""  # SHA-256 of source code
    code_hash_algorithm: str = "sha256"

    # Trust chain
    issuer: str = "self-signed"  # CA that issued this cert
    issuer_key_id: str = ""  # Key ID of the issuing authority
    signature: str = ""  # Issuer's signature over this cert
    trust_level: str = "self-signed"  # self-signed | internal | external

    # Validity
    issued_at: str = ""
    expires_at: str = ""  # Empty = no expiration
    revoked: bool = False
    revocation_reason: str = ""

    # Metadata
    owner: str = ""
    organization: str = ""
    description: str = ""
    permissions: List[str] = field(
        default_factory=list
    )  # e.g. ["read", "write", "execute"]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ToolCertificate":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @property
    def is_valid(self) -> bool:
        """Check if certificate is currently valid (not revoked, not expired)."""
        if self.revoked:
            return False
        if self.expires_at:
            try:
                exp = datetime.fromisoformat(self.expires_at)
                if exp < datetime.now(timezone.utc):
                    return False
            except ValueError:
                pass
        return True

    @property
    def fingerprint(self) -> str:
        """Short fingerprint for display (first 12 chars of code hash)."""
        return self.code_hash[:12] + "..." if self.code_hash else "---"


def compute_code_hash(func: Callable) -> str:
    """Compute SHA-256 hash of a function's source code.

    This is the core integrity check — if anyone modifies the tool's
    code, the hash changes and the certificate becomes invalid.
    """
    try:
        source = inspect.getsource(func)
        # Normalize whitespace to avoid OS-specific line ending issues
        source = source.strip().replace("\r\n", "\n")
        return hashlib.sha256(source.encode("utf-8")).hexdigest()
    except (OSError, TypeError):
        # Can't get source (built-in, C extension, lambda)
        # Fall back to qualified name + module
        fallback = f"{func.__module__}.{func.__qualname__}"
        return hashlib.sha256(fallback.encode("utf-8")).hexdigest()


class ToolRegistry:
    """Certificate Authority + Registry for trusted tools.

    The CISO's control panel — manages which tools are trusted,
    verifies certificates before execution, and logs violations.

    Persistence: stores certificates in .trustchain/certs/ as JSON files.
    """

    def __init__(
        self,
        registry_dir: Optional[str] = None,
        signer: Optional[Signer] = None,
        strict: bool = True,
    ):
        """Initialize the Tool Registry.

        Args:
            registry_dir: Directory for persistent cert storage.
                         Defaults to .trustchain/certs/
            signer: Signer for issuing certificates. If None, uses
                    self-signed mode.
            strict: If True, verification failures raise exceptions.
                    If False, just log warnings.
        """
        self._certs: Dict[str, ToolCertificate] = {}
        self._violations: List[Dict[str, Any]] = []
        self._signer = signer
        self._strict = strict

        # Persistent storage
        if registry_dir:
            self._registry_dir = Path(registry_dir).expanduser().resolve()
        else:
            self._registry_dir = Path(".trustchain/certs").resolve()
        self._registry_dir.mkdir(parents=True, exist_ok=True)

        # Load existing certificates
        self._load_certs()

    def certify(
        self,
        func: Callable,
        owner: str = "",
        organization: str = "",
        description: str = "",
        permissions: Optional[List[str]] = None,
        expires_at: str = "",
        version: str = "1.0.0",
    ) -> ToolCertificate:
        """Issue a certificate for a tool function.

        Computes the code hash, creates a certificate, optionally signs
        it with the registry's key, and stores it.

        Args:
            func: The tool function to certify
            owner: Certificate owner name
            organization: Organization name
            description: Tool description
            permissions: Allowed operations
            expires_at: Expiration datetime (ISO format)
            version: Tool version

        Returns:
            The issued ToolCertificate
        """
        tool_name = func.__qualname__
        tool_module = func.__module__
        code_hash = compute_code_hash(func)

        cert = ToolCertificate(
            tool_name=tool_name,
            tool_module=tool_module,
            version=version,
            code_hash=code_hash,
            issuer="self-signed" if not self._signer else "internal-ca",
            issued_at=datetime.now(timezone.utc).isoformat(),
            expires_at=expires_at,
            owner=owner,
            organization=organization,
            description=description or func.__doc__ or "",
            permissions=permissions or [],
            trust_level="self-signed" if not self._signer else "internal",
        )

        # Sign the certificate if we have a signer
        if self._signer:
            cert_data = json.dumps(
                {
                    "tool_name": cert.tool_name,
                    "tool_module": cert.tool_module,
                    "code_hash": cert.code_hash,
                    "version": cert.version,
                    "issued_at": cert.issued_at,
                },
                sort_keys=True,
            )
            signed = self._signer.sign("cert_issue", cert_data)
            cert.signature = signed.signature
            cert.issuer_key_id = self._signer.key_id

        # Store
        registry_key = f"{tool_module}.{tool_name}"
        self._certs[registry_key] = cert
        self._save_cert(registry_key, cert)

        return cert

    def verify(self, func: Callable) -> bool:
        """Verify a tool's certificate before execution.

        Checks:
        1. Certificate exists in registry
        2. Certificate is not revoked or expired
        3. Code hash matches (no tampering)

        Returns:
            True if tool is trusted, False otherwise
        """
        tool_name = func.__qualname__
        tool_module = func.__module__
        registry_key = f"{tool_module}.{tool_name}"

        # 1. Check certificate exists
        cert = self._certs.get(registry_key)
        if not cert:
            self._record_violation(
                registry_key, "NO_CERTIFICATE", "Tool has no certificate"
            )
            return False

        # 2. Check validity (not revoked, not expired)
        if not cert.is_valid:
            reason = "REVOKED" if cert.revoked else "EXPIRED"
            self._record_violation(
                registry_key, reason, f"Certificate is {reason.lower()}"
            )
            return False

        # 3. Verify code hash (the critical check)
        current_hash = compute_code_hash(func)
        if current_hash != cert.code_hash:
            self._record_violation(
                registry_key,
                "CODE_TAMPERED",
                f"Code hash mismatch: expected {cert.code_hash[:16]}..., got {current_hash[:16]}...",
            )
            return False

        return True

    def revoke(self, func_or_key: Any, reason: str = "Manually revoked") -> bool:
        """Revoke a tool's certificate.

        After revocation, the tool cannot be executed until re-certified.
        """
        if callable(func_or_key):
            key = f"{func_or_key.__module__}.{func_or_key.__qualname__}"
        else:
            key = func_or_key

        cert = self._certs.get(key)
        if not cert:
            return False

        cert.revoked = True
        cert.revocation_reason = reason
        self._save_cert(key, cert)
        return True

    def get_cert(self, func: Callable) -> Optional[ToolCertificate]:
        """Get the certificate for a function."""
        key = f"{func.__module__}.{func.__qualname__}"
        return self._certs.get(key)

    def list_certs(self) -> List[ToolCertificate]:
        """List all registered certificates."""
        return list(self._certs.values())

    @property
    def violations(self) -> List[Dict[str, Any]]:
        """Get all recorded violations."""
        return self._violations.copy()

    # ── Internal ──

    def _record_violation(
        self, tool_key: str, violation_type: str, detail: str
    ) -> None:
        """Record a security violation."""
        self._violations.append(
            {
                "tool": tool_key,
                "type": violation_type,
                "detail": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def _save_cert(self, key: str, cert: ToolCertificate) -> None:
        """Persist certificate to disk."""
        safe_key = key.replace(".", "_").replace("/", "_")
        path = self._registry_dir / f"{safe_key}.json"
        path.write_text(json.dumps(cert.to_dict(), indent=2), encoding="utf-8")

    def _load_certs(self) -> None:
        """Load certificates from disk."""
        for path in self._registry_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                cert = ToolCertificate.from_dict(data)
                key = f"{cert.tool_module}.{cert.tool_name}"
                self._certs[key] = cert
            except (json.JSONDecodeError, KeyError):
                pass


class UntrustedToolError(Exception):
    """Raised when an untrusted tool attempts to execute."""

    def __init__(self, tool_name: str, reason: str):
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"DENY: Untrusted tool '{tool_name}': {reason}")


def trustchain_certified(
    registry: ToolRegistry,
    strict: bool = True,
):
    """Decorator: verify tool certificate before every execution.

    This is the 'SSL handshake' for AI tools. Before the agent can
    call a tool, TrustChain checks its certificate.

    Usage:
        registry = ToolRegistry()
        registry.certify(my_tool)

        @trustchain_certified(registry)
        def my_tool(query: str) -> dict:
            return {"result": "safe"}

        # Now my_tool will verify its certificate on every call.
        # If the code is tampered with, it raises UntrustedToolError.

    Args:
        registry: The ToolRegistry to verify against
        strict: If True, raise UntrustedToolError on failure.
                If False, log warning and allow execution.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not registry.verify(func):
                violations = registry.violations
                last = violations[-1] if violations else {}
                reason = last.get("detail", "No valid certificate")

                if strict:
                    raise UntrustedToolError(func.__qualname__, reason)
                # Non-strict: allow but log

            return func(*args, **kwargs)

        # Mark as certified for introspection
        wrapper._trustchain_certified = True
        wrapper._trustchain_registry = registry
        return wrapper

    return decorator
