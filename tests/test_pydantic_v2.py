"""Tests for Pydantic v2 integration."""

import pytest

try:
    from pydantic import BaseModel

    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

pytestmark = pytest.mark.skipif(not HAS_PYDANTIC, reason="Pydantic v2 not installed")

from trustchain.integrations.pydantic_v2 import SignedDict, SignedField, TrustChainModel


class TestTrustChainModel:
    """Test TrustChainModel functionality."""

    def test_create_model(self):
        """Test basic model creation."""

        class SearchResult(TrustChainModel):
            query: str
            results: list
            count: int

        result = SearchResult(query="test", results=["doc1"], count=1)

        assert result.query == "test"
        assert result.results == ["doc1"]
        assert result.count == 1

    def test_auto_signed(self):
        """Test model is auto-signed on creation."""

        class AIResponse(TrustChainModel):
            answer: str

        response = AIResponse(answer="42")

        assert response.is_signed is True
        assert response.signature != ""
        assert len(response.signature) > 10

    def test_verify_valid(self):
        """Test verification of valid model."""

        class Result(TrustChainModel):
            value: int

        result = Result(value=100)

        assert result.verify() is True

    def test_verify_tampered(self):
        """Test verification fails on tampered data."""

        class Result(TrustChainModel):
            value: int

        result = Result(value=100)

        # Tamper with data (bypass validation)
        object.__setattr__(result, "value", 999)

        # Verification should fail because data changed
        assert result.verify() is False

    def test_signature_id(self):
        """Test signature ID is unique."""

        class Item(TrustChainModel):
            name: str

        item1 = Item(name="one")
        item2 = Item(name="two")

        assert item1.signature_id != item2.signature_id

    def test_timestamp(self):
        """Test timestamp is set."""

        class Item(TrustChainModel):
            name: str

        item = Item(name="test")

        assert item.timestamp > 0

    def test_to_signed_response(self):
        """Test conversion to SignedResponse."""
        from trustchain import SignedResponse

        class Result(TrustChainModel):
            answer: str

        result = Result(answer="42")
        response = result.to_signed_response()

        assert isinstance(response, SignedResponse)
        assert response.tool_id == "Result"
        assert response.data == {"answer": "42"}
        assert response.signature == result.signature

    def test_from_signed_response(self):
        """Test creation from SignedResponse."""
        from trustchain import TrustChain

        class SearchResult(TrustChainModel):
            query: str
            count: int

        tc = TrustChain()
        response = tc._signer.sign("SearchResult", {"query": "test", "count": 5})

        result = SearchResult.from_signed_response(response)

        assert result.query == "test"
        assert result.count == 5
        assert result.signature == response.signature


class TestSignedField:
    """Test SignedField function."""

    def test_signed_field_with_min_max(self):
        """Test SignedField with min/max constraints."""

        class Prediction(TrustChainModel):
            confidence: float = SignedField(min=0, max=1)

        # Valid value
        pred = Prediction(confidence=0.5)
        assert pred.confidence == 0.5

    def test_signed_field_validation(self):
        """Test SignedField validation."""
        from pydantic import ValidationError

        class Prediction(TrustChainModel):
            confidence: float = SignedField(min=0, max=1)

        # Invalid value should raise
        with pytest.raises(ValidationError):
            Prediction(confidence=1.5)

    def test_signed_field_with_default(self):
        """Test SignedField with default value."""

        class Config(TrustChainModel):
            timeout: int = SignedField(default=30)

        config = Config()
        assert config.timeout == 30


class TestSignedDict:
    """Test SignedDict functionality."""

    def test_create_signed_dict(self):
        """Test basic SignedDict creation."""
        data = SignedDict({"key": "value", "count": 5})

        assert data["key"] == "value"
        assert data["count"] == 5

    def test_signed_dict_is_signed(self):
        """Test SignedDict is auto-signed."""
        data = SignedDict({"value": 42})

        assert data.is_signed is True
        assert data.signature != ""

    def test_signed_dict_verify(self):
        """Test SignedDict verification."""
        data = SignedDict({"query": "test"})

        assert data.verify() is True

    def test_signed_dict_tampered(self):
        """Test SignedDict verification fails on tampering."""
        data = SignedDict({"value": 100})

        # Tamper with data
        data["value"] = 999

        assert data.verify() is False

    def test_signed_dict_to_response(self):
        """Test SignedDict to SignedResponse conversion."""
        from trustchain import SignedResponse

        data = SignedDict({"result": "ok"}, tool_id="MyTool")
        response = data.to_signed_response()

        assert isinstance(response, SignedResponse)
        assert response.tool_id == "MyTool"
        assert response.data == {"result": "ok"}


class TestModelInheritance:
    """Test model inheritance scenarios."""

    def test_inherited_model(self):
        """Test inherited models are signed."""

        class BaseResult(TrustChainModel):
            status: str

        class DetailedResult(BaseResult):
            details: str

        result = DetailedResult(status="ok", details="all good")

        assert result.is_signed
        assert result.verify()

    def test_multiple_subclasses(self):
        """Test multiple subclasses have independent signers."""

        class TypeA(TrustChainModel):
            a: int

        class TypeB(TrustChainModel):
            b: int

        a = TypeA(a=1)
        b = TypeB(b=2)

        # Both should be signed independently
        assert a.is_signed
        assert b.is_signed
        assert a.signature != b.signature
