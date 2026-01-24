"""Pydantic v2 integration for TrustChain.

Auto-sign Pydantic models on creation for seamless integration.

Example:
    from trustchain.integrations.pydantic_v2 import TrustChainModel

    class AIResponse(TrustChainModel):
        answer: str
        sources: list[str]
        confidence: float

    # Auto-signed on creation
    response = AIResponse(answer="42", sources=["doc1"], confidence=0.95)
    assert response.is_signed
    assert response.verify()
"""

from __future__ import annotations

import time
import uuid
from typing import Any, ClassVar, TypeVar

try:
    from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    BaseModel = object  # type: ignore

from trustchain.v2.signer import SignedResponse, Signer

T = TypeVar("T", bound="TrustChainModel")


def SignedField(
    default: Any = ...,
    *,
    description: str = "",
    min: float | None = None,
    max: float | None = None,
    **kwargs,
) -> Any:
    """Mark a field as part of the signature computation.

    By default, all fields are included. Use this to add validation.

    Example:
        confidence: float = SignedField(min=0, max=1)
    """
    if not HAS_PYDANTIC:
        return default

    field_kwargs = {"description": description, **kwargs}

    if min is not None:
        field_kwargs["ge"] = min
    if max is not None:
        field_kwargs["le"] = max

    if default is not ...:
        field_kwargs["default"] = default

    return Field(**field_kwargs)


class TrustChainModel(BaseModel if HAS_PYDANTIC else object):  # type: ignore
    """Pydantic model with automatic cryptographic signing.

    All fields are signed on model creation. The signature is stored
    in `_signature` and can be verified with `verify()`.

    Example:
        class SearchResult(TrustChainModel):
            query: str
            results: list[str]
            count: int

        result = SearchResult(query="AI safety", results=["doc1"], count=1)
        assert result.is_signed
        assert result.verify()
    """

    if HAS_PYDANTIC:
        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

    # Private attributes for signing
    _signature: str = PrivateAttr(default="")
    _signature_id: str = PrivateAttr(default_factory=lambda: str(uuid.uuid4()))
    _timestamp: float = PrivateAttr(default_factory=time.time)
    _nonce: str = PrivateAttr(default_factory=lambda: str(uuid.uuid4()))
    _signer: ClassVar[Signer | None] = None

    def __init__(self, **data):
        if not HAS_PYDANTIC:
            raise ImportError(
                "Pydantic v2 required for TrustChainModel. "
                "Install with: pip install pydantic>=2.0.0"
            )
        super().__init__(**data)
        self._sign()

    def __init_subclass__(cls, **kwargs):
        """Initialize signer for subclass if not already set."""
        super().__init_subclass__(**kwargs)
        if cls._signer is None:
            cls._signer = Signer()

    def _sign(self) -> None:
        """Sign the model data."""
        if self._signer is None:
            self.__class__._signer = Signer()

        # Simple signature using signer
        response = self._signer.sign(
            tool_id=self.__class__.__name__,
            data=self.model_dump(),
            nonce=self._nonce,
        )
        self._signature = response.signature
        self._timestamp = response.timestamp

    def _get_canonical_data(self) -> dict[str, Any]:
        """Get canonical representation for signing."""
        return {
            "model": self.__class__.__name__,
            "data": self.model_dump(),
            "timestamp": self._timestamp,
        }

    @property
    def is_signed(self) -> bool:
        """Check if model is signed."""
        return bool(self._signature)

    @property
    def signature(self) -> str:
        """Get the signature."""
        return self._signature

    @property
    def signature_id(self) -> str:
        """Get unique signature ID."""
        return self._signature_id

    @property
    def timestamp(self) -> float:
        """Get signing timestamp."""
        return self._timestamp

    def verify(self) -> bool:
        """Verify the model signature.

        Returns:
            True if signature is valid and data hasn't been tampered.
        """
        if not self._signature or self._signer is None:
            return False

        # Re-create signed response for verification
        response = SignedResponse(
            tool_id=self.__class__.__name__,
            data=self.model_dump(),
            signature=self._signature,
            timestamp=self._timestamp,
            nonce=self._nonce,
        )

        return self._signer.verify(response)

    def to_signed_response(self) -> SignedResponse:
        """Convert to SignedResponse for chain integration.

        Example:
            chain = [model1.to_signed_response(), model2.to_signed_response()]
            tc.verify_chain(chain)
        """
        return SignedResponse(
            tool_id=self.__class__.__name__,
            data=self.model_dump(),
            signature=self._signature,
            signature_id=self._signature_id,
            timestamp=self._timestamp,
            nonce=None,
        )

    @classmethod
    def from_signed_response(cls: type[T], response: SignedResponse) -> T:
        """Create model from SignedResponse.

        Example:
            response = tc.sign("SearchResult", {"query": "test", "results": []})
            model = SearchResult.from_signed_response(response)
        """
        instance = cls(**response.data)
        instance._signature = response.signature
        instance._timestamp = response.timestamp
        return instance


class SignedDict(dict):
    """Dictionary with cryptographic signature.

    For cases when you don't want to define a model class.

    Example:
        data = SignedDict({"query": "test", "results": ["doc1"]})
        assert data.verify()
    """

    def __init__(self, data: dict[str, Any], tool_id: str = "SignedDict"):
        super().__init__(data)
        self._signer = Signer()
        self._tool_id = tool_id

        response = self._signer.sign(tool_id=tool_id, data=dict(self))
        self._signature = response.signature
        self._timestamp = response.timestamp
        self._signature_id = response.signature_id
        self._nonce = response.nonce

    @property
    def signature(self) -> str:
        return self._signature

    @property
    def is_signed(self) -> bool:
        return bool(self._signature)

    def verify(self) -> bool:
        """Verify the signature."""
        response = SignedResponse(
            tool_id=self._tool_id,
            data=dict(self),
            signature=self._signature,
            timestamp=self._timestamp,
            nonce=self._nonce,
        )
        return self._signer.verify(response)

    def to_signed_response(self) -> SignedResponse:
        """Convert to SignedResponse."""
        return SignedResponse(
            tool_id=self._tool_id,
            data=dict(self),
            signature=self._signature,
            signature_id=self._signature_id,
            timestamp=self._timestamp,
        )
