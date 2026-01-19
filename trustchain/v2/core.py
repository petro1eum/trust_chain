"""Core TrustChain v2 implementation."""

import asyncio
import base64
import functools
import json
import os
import time
from typing import Any, Callable, Dict, Optional, Union

from trustchain.utils.exceptions import NonceReplayError

from .config import TrustChainConfig
from .metrics import get_metrics
from .nonce_storage import NonceStorage, create_nonce_storage
from .signer import SignedResponse, Signer
from .storage import MemoryStorage, Storage


class TrustChain:
    """Simple API for cryptographically signed tool responses."""

    def __init__(self, config: Optional[TrustChainConfig] = None):
        """Initialize TrustChain with optional configuration."""
        self.config = config or TrustChainConfig()
        self._signer = self._load_or_create_signer()
        self._storage = self._create_storage()
        self._tools: Dict[str, Dict[str, Any]] = {}

        # Nonce tracking for replay protection
        if self.config.enable_nonce:
            self._nonce_storage = create_nonce_storage(
                backend=self.config.nonce_backend,
                redis_url=self.config.redis_url,
                tenant_id=self.config.tenant_id,
            )
        else:
            self._nonce_storage: Optional[NonceStorage] = None

        # Enterprise: Prometheus metrics
        self._metrics = get_metrics(self.config.enable_metrics)

    def _load_or_create_signer(self) -> Signer:
        """Load signer from persistence or create new one."""
        # Try loading from environment variable
        if self.config.key_env_var:
            env_value = os.environ.get(self.config.key_env_var)
            if env_value:
                try:
                    key_data = json.loads(base64.b64decode(env_value).decode())
                    return Signer.from_keys(key_data)
                except Exception:
                    pass  # Fall through to file or new key

        # Try loading from file
        if self.config.key_file and os.path.exists(self.config.key_file):
            try:
                with open(self.config.key_file) as f:
                    key_data = json.load(f)
                return Signer.from_keys(key_data)
            except Exception:
                pass  # Fall through to new key

        # Create new signer
        return Signer(self.config.algorithm)

    def _create_storage(self) -> Storage:
        """Create storage backend based on config."""
        if self.config.storage_backend == "memory":
            return MemoryStorage(self.config.max_cached_responses)
        else:
            raise ValueError(f"Unknown storage backend: {self.config.storage_backend}")

    def tool(self, tool_id: str, **options) -> Callable:
        """
        Decorator to create a cryptographically signed tool.

        Example:
            @tc.tool("weather_api")
            def get_weather(city: str):
                return {"temp": 20, "city": city}
        """

        def decorator(func: Callable) -> Callable:
            # Store tool metadata
            self._tools[tool_id] = {
                "func": func,
                "original_func": func,  # For schema generation
                "description": options.get("description", func.__doc__),
                "options": options,
                "created_at": time.time(),
                "call_count": 0,
            }

            # Create wrapper based on function type
            if asyncio.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args, **kwargs) -> SignedResponse:
                    return await self._execute_tool_async(tool_id, func, args, kwargs)

                return async_wrapper
            else:

                @functools.wraps(func)
                def sync_wrapper(*args, **kwargs) -> SignedResponse:
                    return self._execute_tool_sync(tool_id, func, args, kwargs)

                return sync_wrapper

        return decorator

    def _execute_tool_sync(
        self, tool_id: str, func: Callable, args: tuple, kwargs: dict
    ) -> SignedResponse:
        """Execute a synchronous tool and sign the response."""
        # Update call count
        self._tools[tool_id]["call_count"] += 1

        try:
            # Execute the tool
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time

            # Generate nonce if enabled
            nonce = None
            if self.config.enable_nonce:
                nonce = self._generate_nonce()

            # Sign the response
            signed_response = self._signer.sign(tool_id, result, nonce)

            # Store in cache if enabled
            if self.config.enable_cache:
                self._storage.store(
                    signed_response.signature_id,
                    signed_response,
                    ttl=self.config.cache_ttl,
                )

            # Track execution time
            self._tools[tool_id]["last_execution_time"] = execution_time

            return signed_response

        except Exception as e:
            # Track errors
            self._tools[tool_id]["last_error"] = str(e)
            raise

    async def _execute_tool_async(
        self, tool_id: str, func: Callable, args: tuple, kwargs: dict
    ) -> SignedResponse:
        """Execute an asynchronous tool and sign the response."""
        # Update call count
        self._tools[tool_id]["call_count"] += 1

        try:
            # Execute the tool
            start_time = time.time()
            result = await func(*args, **kwargs)
            execution_time = time.time() - start_time

            # Generate nonce if enabled
            nonce = None
            if self.config.enable_nonce:
                nonce = self._generate_nonce()

            # Sign the response
            signed_response = self._signer.sign(tool_id, result, nonce)

            # Store in cache if enabled
            if self.config.enable_cache:
                self._storage.store(
                    signed_response.signature_id,
                    signed_response,
                    ttl=self.config.cache_ttl,
                )

            # Track execution time
            self._tools[tool_id]["last_execution_time"] = execution_time

            return signed_response

        except Exception as e:
            # Track errors
            self._tools[tool_id]["last_error"] = str(e)
            raise

    def verify(self, response: Union[SignedResponse, Dict[str, Any]]) -> bool:
        """Verify a signed response.

        Raises:
            NonceReplayError: If nonce was already used (replay attack detected)
        """
        # Convert dict to SignedResponse if needed
        if isinstance(response, dict):
            response = SignedResponse(**response)

        # Check nonce for replay protection (if enabled)
        if self._nonce_storage and response.nonce:
            # check_and_add returns False if nonce already exists
            if not self._nonce_storage.check_and_add(
                response.nonce, self.config.nonce_ttl
            ):
                raise NonceReplayError(
                    response.nonce,
                    message=f"Replay attack detected: nonce '{response.nonce[:8]}...' already used",
                )

        # Verify cryptographic signature
        is_valid = self._signer.verify(response)

        # Cache verification result
        response._verified = is_valid

        return is_valid

    def verify_chain(self, responses: list) -> bool:
        """Verify a chain of linked SignedResponses.

        Each response (except first) must have parent_signature
        matching the previous response's signature.

        Args:
            responses: List of SignedResponse in order

        Returns:
            True if all signatures valid and chain is unbroken
        """
        if not responses:
            return True

        # Verify first response
        if not self.verify(responses[0]):
            return False

        # Verify chain links
        for i in range(1, len(responses)):
            current = responses[i]
            previous = responses[i - 1]

            # Check chain link
            if current.parent_signature != previous.signature:
                return False

            # Verify signature
            if not self._signer.verify(current):
                return False

        return True

    def _generate_nonce(self) -> str:
        """Generate a unique nonce.

        Note: Nonces are NOT added to _used_nonces here.
        They are tracked only during verify() to detect replay attacks.
        """
        import uuid

        return str(uuid.uuid4())

    def _check_nonce(self, nonce: str) -> bool:
        """Check if nonce is valid and not already used."""
        if nonce in self._used_nonces:
            return False
        self._used_nonces.append(nonce)
        return True

    def get_tool_stats(self, tool_id: str) -> Dict[str, Any]:
        """Get statistics for a specific tool."""
        if tool_id not in self._tools:
            raise ValueError(f"Unknown tool: {tool_id}")

        tool_info = self._tools[tool_id]
        return {
            "tool_id": tool_id,
            "call_count": tool_info["call_count"],
            "created_at": tool_info["created_at"],
            "last_execution_time": tool_info.get("last_execution_time"),
            "last_error": tool_info.get("last_error"),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get overall statistics."""
        total_calls = sum(t["call_count"] for t in self._tools.values())

        return {
            "total_tools": len(self._tools),
            "total_calls": total_calls,
            "cache_size": self._storage.size() if hasattr(self._storage, "size") else 0,
            "signer_key_id": self._signer.get_key_id(),
        }

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._storage.clear()

    # === Schema Export Methods ===

    def get_tool_schema(self, tool_id: str, format: str = "openai") -> dict:
        """Get OpenAI/Anthropic schema for a tool.

        Args:
            tool_id: Tool identifier
            format: 'openai' or 'anthropic'

        Returns:
            Function schema dict
        """
        from .schemas import generate_anthropic_schema, generate_function_schema

        if tool_id not in self._tools:
            raise ValueError(f"Unknown tool: {tool_id}")

        tool_info = self._tools[tool_id]
        func = tool_info["original_func"]
        desc = tool_info.get("description")

        if format == "anthropic":
            return generate_anthropic_schema(func, tool_id, desc)
        return generate_function_schema(func, tool_id, desc)

    def get_tools_schema(self, format: str = "openai") -> list:
        """Get schemas for all registered tools.

        Args:
            format: 'openai' or 'anthropic'

        Returns:
            List of function schemas
        """
        return [self.get_tool_schema(tid, format) for tid in self._tools]

    # === Key Persistence Methods ===

    def export_keys(self) -> dict:
        """Export signer keys for persistence.

        Returns:
            dict with key material that can be saved to file or env var
        """
        return self._signer.export_keys()

    def save_keys(self, filepath: Optional[str] = None) -> str:
        """Save signer keys to file.

        Args:
            filepath: Path to save keys. Uses config.key_file if not provided.

        Returns:
            Path where keys were saved
        """
        path = filepath or self.config.key_file
        if not path:
            raise ValueError("No filepath provided and config.key_file not set")

        key_data = self.export_keys()
        with open(path, "w") as f:
            json.dump(key_data, f, indent=2)

        return path

    def export_public_key(self) -> str:
        """Export public key for external verification.

        Returns:
            Base64-encoded public key
        """
        return self._signer.get_public_key()

    def get_key_id(self) -> str:
        """Get unique identifier for current signing key."""
        return self._signer.get_key_id()
