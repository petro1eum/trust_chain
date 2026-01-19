"""Tests for trustchain/v2/verifier.py - External verification."""

import pytest

from trustchain import TrustChain, TrustChainVerifier, VerificationResult


class TestTrustChainVerifier:
    """Test external signature verification."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    @pytest.fixture
    def verifier(self, tc):
        public_key = tc.export_public_key()
        return TrustChainVerifier(public_key)

    def test_create_verifier(self, tc):
        """Test verifier creation from public key."""
        public_key = tc.export_public_key()
        verifier = TrustChainVerifier(public_key)
        assert verifier is not None

    def test_verify_valid_signature(self, tc, verifier):
        """Test verifying a valid signature."""
        signed = tc._signer.sign("test", {"value": 42})

        result = verifier.verify(signed)

        assert result.valid is True
        assert result.tool_id == "test"

    def test_verify_returns_result_object(self, tc, verifier):
        """Test that verify returns VerificationResult."""
        signed = tc._signer.sign("test", {"data": 1})

        result = verifier.verify(signed)

        assert isinstance(result, VerificationResult)
        assert hasattr(result, "valid")
        assert hasattr(result, "tool_id")

    def test_verify_tampered_data(self, tc, verifier):
        """Test that tampered data fails verification."""
        signed = tc._signer.sign("test", {"original": True})

        # Tamper with data
        signed.data = {"tampered": True}

        result = verifier.verify(signed)

        assert result.valid is False

    def test_verify_wrong_signature(self, tc, verifier):
        """Test that wrong signature fails verification."""
        signed = tc._signer.sign("test", {"value": 1})

        # Replace with invalid signature
        signed.signature = "invalid_signature_base64"

        result = verifier.verify(signed)

        assert result.valid is False


class TestVerifierWithDifferentKeys:
    """Test that verifier works only with matching keys."""

    def test_different_key_fails(self):
        """Test that different key fails verification."""
        tc1 = TrustChain()
        tc2 = TrustChain()

        # Sign with tc1
        signed = tc1._signer.sign("test", {"data": 1})

        # Try to verify with tc2's key
        verifier = TrustChainVerifier(tc2.export_public_key())
        result = verifier.verify(signed)

        assert result.valid is False

    def test_same_key_succeeds(self):
        """Test that same key succeeds verification."""
        tc = TrustChain()

        signed = tc._signer.sign("test", {"data": 1})

        verifier = TrustChainVerifier(tc.export_public_key())
        result = verifier.verify(signed)

        assert result.valid is True


class TestVerificationResult:
    """Test VerificationResult dataclass."""

    def test_valid_result(self):
        """Test creating valid result."""
        result = VerificationResult(
            valid=True,
            tool_id="test_tool",
            key_id="key-123",
        )

        assert result.valid is True
        assert result.is_verified is True
        assert result.tool_id == "test_tool"

    def test_invalid_result_with_error(self):
        """Test creating invalid result with error."""
        result = VerificationResult(
            valid=False,
            tool_id="test_tool",
            error="Signature mismatch",
        )

        assert result.valid is False
        assert result.is_verified is False
        assert result.error == "Signature mismatch"
