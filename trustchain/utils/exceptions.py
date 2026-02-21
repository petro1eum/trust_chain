"""Custom exceptions for TrustChain."""

from typing import Any, Dict, Optional


class TrustChainError(Exception):
    """Base exception for all TrustChain errors."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def __str__(self) -> str:
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message


class SignatureVerificationError(TrustChainError):
    """Raised when signature verification fails."""

    def __init__(
        self,
        message: str = "Signature verification failed",
        signature_id: Optional[str] = None,
        tool_id: Optional[str] = None,
        **kwargs: Any,
    ):
        details = kwargs.get("details", {})
        if signature_id:
            details["signature_id"] = signature_id
        if tool_id:
            details["tool_id"] = tool_id

        super().__init__(
            message, error_code="SIGNATURE_VERIFICATION_FAILED", details=details
        )
        self.signature_id = signature_id
        self.tool_id = tool_id


class NonceReplayError(TrustChainError):
    """Raised when a nonce is reused (replay attack detected)."""

    def __init__(
        self, nonce: str, message: str = "Nonce replay detected", **kwargs: Any
    ) -> None:
        details = kwargs.get("details", {})
        details["nonce"] = nonce

        super().__init__(message, error_code="NONCE_REPLAY_DETECTED", details=details)
        self.nonce = nonce


class KeyNotFoundError(TrustChainError):
    """Raised when a cryptographic key is not found in the registry."""

    def __init__(
        self, key_id: str, message: Optional[str] = None, **kwargs: Any
    ) -> None:
        if message is None:
            message = f"Key not found: {key_id}"

        details = kwargs.get("details", {})
        details["key_id"] = key_id

        super().__init__(message, error_code="KEY_NOT_FOUND", details=details)
        self.key_id = key_id


class ChainIntegrityError(TrustChainError):
    """Raised when chain of trust integrity is compromised."""

    def __init__(
        self,
        chain_id: str,
        step_number: Optional[int] = None,
        message: Optional[str] = None,
        **kwargs: Any,
    ):
        if message is None:
            if step_number is not None:
                message = (
                    f"Chain integrity error at step {step_number} in chain {chain_id}"
                )
            else:
                message = f"Chain integrity error in chain {chain_id}"

        details = kwargs.get("details", {})
        details["chain_id"] = chain_id
        if step_number is not None:
            details["step_number"] = step_number

        super().__init__(message, error_code="CHAIN_INTEGRITY_ERROR", details=details)
        self.chain_id = chain_id
        self.step_number = step_number


class RegistryError(TrustChainError):
    """Raised when trust registry operations fail."""

    def __init__(
        self,
        message: str,
        registry_type: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        details = kwargs.get("details", {})
        if registry_type:
            details["registry_type"] = registry_type
        if operation:
            details["operation"] = operation

        super().__init__(message, error_code="REGISTRY_ERROR", details=details)
        self.registry_type = registry_type
        self.operation = operation


class ConfigurationError(TrustChainError):
    """Raised when configuration is invalid or missing."""

    def __init__(
        self, message: str, config_key: Optional[str] = None, **kwargs: Any
    ) -> None:
        details = kwargs.get("details", {})
        if config_key:
            details["config_key"] = config_key

        super().__init__(message, error_code="CONFIGURATION_ERROR", details=details)
        self.config_key = config_key


class CryptoError(TrustChainError):
    """Raised when cryptographic operations fail."""

    def __init__(
        self,
        message: str,
        algorithm: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        details = kwargs.get("details", {})
        if algorithm:
            details["algorithm"] = algorithm
        if operation:
            details["operation"] = operation

        super().__init__(message, error_code="CRYPTO_ERROR", details=details)
        self.algorithm = algorithm
        self.operation = operation


class ToolExecutionError(TrustChainError):
    """Raised when trusted tool execution fails."""

    def __init__(
        self,
        tool_id: str,
        message: str,
        original_error: Optional[Exception] = None,
        **kwargs: Any,
    ):
        details = kwargs.get("details", {})
        details["tool_id"] = tool_id
        if original_error:
            details["original_error"] = str(original_error)
            details["original_error_type"] = type(original_error).__name__

        super().__init__(message, error_code="TOOL_EXECUTION_ERROR", details=details)
        self.tool_id = tool_id
        self.original_error = original_error


class NetworkError(TrustChainError):
    """Raised when network operations fail."""

    def __init__(
        self,
        message: str,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        **kwargs: Any,
    ):
        details = kwargs.get("details", {})
        if endpoint:
            details["endpoint"] = endpoint
        if status_code:
            details["status_code"] = status_code

        super().__init__(message, error_code="NETWORK_ERROR", details=details)
        self.endpoint = endpoint
        self.status_code = status_code


# Convenience functions for creating exceptions with context
def signature_error(message: str, **context: Any) -> SignatureVerificationError:
    """Create a SignatureVerificationError with context."""
    return SignatureVerificationError(message, **context)


def nonce_replay_error(nonce: str, **context: Any) -> NonceReplayError:
    """Create a NonceReplayError with context."""
    return NonceReplayError(nonce, **context)


def key_not_found_error(key_id: str, **context: Any) -> KeyNotFoundError:
    """Create a KeyNotFoundError with context."""
    return KeyNotFoundError(key_id, **context)


def chain_integrity_error(chain_id: str, **context: Any) -> ChainIntegrityError:
    """Create a ChainIntegrityError with context."""
    return ChainIntegrityError(chain_id, **context)


def config_error(message: str, **context: Any) -> ConfigurationError:
    """Create a ConfigurationError with context."""
    return ConfigurationError(message, **context)
