"""External verifier for TrustChain responses.

This module provides verification-only functionality for third parties
who want to verify signed responses without signing capability.
"""

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from .signer import SignedResponse


@dataclass
class VerificationResult:
    """Result of signature verification."""

    valid: bool
    tool_id: str
    key_id: Optional[str] = None
    error: Optional[str] = None

    @property
    def is_verified(self) -> bool:
        return self.valid


class TrustChainVerifier:
    """Verify TrustChain signatures without signing capability.

    Use this when you need to verify responses from another system
    but don't need to sign responses yourself.

    Example:
        # Get public key from the signing system
        public_key = signing_system.export_public_key()

        # Create verifier
        verifier = TrustChainVerifier(public_key)

        # Verify responses
        result = verifier.verify(signed_response)
        if result.valid:
            print("Response is authentic!")
    """

    def __init__(self, public_key: str, key_id: Optional[str] = None):
        """Initialize verifier with public key.

        Args:
            public_key: Base64-encoded Ed25519 public key
            key_id: Optional key identifier for logging
        """
        if not HAS_CRYPTOGRAPHY:
            raise ValueError("cryptography library required for verification")

        self._public_key_b64 = public_key
        self._key_id = key_id

        try:
            public_bytes = base64.b64decode(public_key)
            self._public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        except Exception as e:
            raise ValueError(f"Invalid public key: {e}")

    def verify(
        self, response: Union[SignedResponse, Dict[str, Any]]
    ) -> VerificationResult:
        """Verify a signed response.

        Args:
            response: SignedResponse or dict with signature data

        Returns:
            VerificationResult with valid=True if signature is authentic
        """
        # Convert dict to SignedResponse if needed
        if isinstance(response, dict):
            try:
                response = SignedResponse(**response)
            except Exception as e:
                return VerificationResult(
                    valid=False,
                    tool_id="unknown",
                    key_id=self._key_id,
                    error=f"Invalid response format: {e}",
                )

        try:
            # Recreate canonical data (must match signer.py format exactly)
            canonical_data = {
                "tool_id": response.tool_id,
                "data": response.data,
                "timestamp": response.timestamp,
                "nonce": response.nonce,
                "parent_signature": response.parent_signature,
            }

            # Serialize to JSON (same format as signer)
            json_data = json.dumps(
                canonical_data, sort_keys=True, separators=(",", ":")
            )

            # Verify signature
            signature_bytes = base64.b64decode(response.signature)
            self._public_key.verify(signature_bytes, json_data.encode("utf-8"))

            return VerificationResult(
                valid=True,
                tool_id=response.tool_id,
                key_id=self._key_id,
            )

        except Exception as e:
            return VerificationResult(
                valid=False,
                tool_id=response.tool_id,
                key_id=self._key_id,
                error=f"Verification failed: {e}",
            )

    def get_public_key(self) -> str:
        """Get the public key being used for verification."""
        return self._public_key_b64

    @classmethod
    def from_key_file(cls, filepath: str) -> "TrustChainVerifier":
        """Create verifier from exported key file.

        Args:
            filepath: Path to JSON key file (from TrustChain.save_keys())

        Returns:
            TrustChainVerifier instance
        """
        with open(filepath) as f:
            key_data = json.load(f)

        if key_data.get("type") == "fallback":
            raise ValueError("Cannot verify fallback signatures externally")

        # For Ed25519, we need to derive public key from private
        if key_data.get("type") == "ed25519":
            private_bytes = base64.b64decode(key_data["private_key"])
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes_raw()
            public_key_b64 = base64.b64encode(public_bytes).decode("ascii")

            return cls(public_key_b64, key_id=key_data.get("key_id"))

        raise ValueError(f"Unknown key type: {key_data.get('type')}")
