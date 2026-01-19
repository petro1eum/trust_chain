"""Tests for trustchain/v2/verifier.py - External verification."""

import pytest

from trustchain import TrustChain
from trustchain.v2.verifier import ExternalVerifier, VerificationResult


class TestExternalVerifier:
    """Test external signature verification."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    @pytest.fixture
    def verifier(self, tc):
        public_key = tc._signer._public_key
        return ExternalVerifier(public_key)

    def test_create_verifier(self, tc):
        verifier = ExternalVerifier(tc._signer._public_key)
        assert verifier is not None

    def test_verify_valid_signature(self, tc, verifier):
        signed = tc._signer.sign("test", {"value": 42})

        result = verifier.verify(signed)

        assert result.is_valid is True

    def test_verify_returns_result_object(self, tc, verifier):
        signed = tc._signer.sign("test", {"data": 1})

        result = verifier.verify(signed)

        assert isinstance(result, VerificationResult)
        assert hasattr(result, "is_valid")
        assert hasattr(result, "signature_id")

    def test_verify_tampered_data(self, tc, verifier):
        signed = tc._signer.sign("test", {"original": True})

        # Tamper with data
        signed.data = {"tampered": True}

        result = verifier.verify(signed)

        assert result.is_valid is False

    def test_verify_wrong_signature(self, tc, verifier):
        signed = tc._signer.sign("test", {"value": 1})

        # Replace signature
        signed.signature = "invalid_signature_base64"

        result = verifier.verify(signed)

        assert result.is_valid is False


class TestVerifierWithDifferentKeys:
    """Test that verifier works only with matching keys."""

    def test_different_key_fails(self):
        tc1 = TrustChain()
        tc2 = TrustChain()

        # Sign with tc1
        signed = tc1._signer.sign("test", {"data": 1})

        # Try to verify with tc2's key
        verifier = ExternalVerifier(tc2._signer._public_key)
        result = verifier.verify(signed)

        assert result.is_valid is False

    def test_same_key_succeeds(self):
        tc = TrustChain()

        signed = tc._signer.sign("test", {"data": 1})

        verifier = ExternalVerifier(tc._signer._public_key)
        result = verifier.verify(signed)

        assert result.is_valid is True


class TestVerifierFromKeyId:
    """Test creating verifier from key ID."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    def test_create_from_key_export(self, tc):
        # Export key info
        key_info = tc._signer.export_public_key()

        # Create verifier from exported key
        verifier = ExternalVerifier.from_exported_key(key_info)

        # Should verify correctly
        signed = tc._signer.sign("test", {"value": 1})
        result = verifier.verify(signed)

        assert result.is_valid is True


class TestVerificationResult:
    """Test VerificationResult dataclass."""

    def test_valid_result(self):
        result = VerificationResult(
            is_valid=True,
            signature_id="sig-123",
            tool_id="test_tool",
            timestamp=1234567890,
        )

        assert result.is_valid is True
        assert result.signature_id == "sig-123"

    def test_invalid_result_with_reason(self):
        result = VerificationResult(is_valid=False, reason="Signature mismatch")

        assert result.is_valid is False
        assert result.reason == "Signature mismatch"
