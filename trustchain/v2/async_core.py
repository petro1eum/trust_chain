"""Async TrustChain implementation for async-first frameworks.

Provides native async/await support for FastAPI, LangChain, LlamaIndex, etc.

Example:
    from trustchain import AsyncTrustChain

    async with AsyncTrustChain() as tc:
        @tc.tool("fetch")
        async def fetch_data(url: str) -> dict:
            async with httpx.AsyncClient() as client:
                return (await client.get(url)).json()

        result = await fetch_data("https://api.example.com")
        assert await tc.verify(result)
"""

import asyncio
import functools
import time
from typing import Any, Callable, Dict, List, Optional, Union

from .config import TrustChainConfig
from .nonce_storage import NonceStorage, create_nonce_storage
from .signer import SignedResponse, Signer
from .storage import MemoryStorage, Storage


class AsyncTrustChain:
    """Async-native TrustChain for modern async frameworks.

    All methods are async and can be awaited directly.
    Thread-safe via asyncio.Lock for nonce tracking.

    Example:
        async with AsyncTrustChain() as tc:
            result = await tc.sign("tool_id", {"data": "value"})
            verified = await tc.verify(result)
    """

    def __init__(self, config: Optional[TrustChainConfig] = None):
        """Initialize AsyncTrustChain with optional configuration."""
        self.config = config or TrustChainConfig()
        self._signer = Signer(algorithm=self.config.algorithm)
        self._storage: Storage = MemoryStorage()
        self._tools: Dict[str, Callable] = {}
        self._lock = asyncio.Lock()

        # Nonce storage for replay protection
        self._nonce_storage: Optional[NonceStorage] = None
        if self.config.enable_nonce:
            self._nonce_storage = create_nonce_storage(self.config.nonce_backend)

    async def __aenter__(self) -> "AsyncTrustChain":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        pass

    def tool(self, tool_id: str, **options) -> Callable:
        """Decorator to create a cryptographically signed async tool.

        Works with both async and sync functions.

        Example:
            @tc.tool("weather_api")
            async def get_weather(city: str):
                return {"temp": 20, "city": city}
        """

        def decorator(func: Callable) -> Callable:
            self._tools[tool_id] = func

            if asyncio.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args, **kwargs):
                    return await self._execute_tool(tool_id, func, args, kwargs)

                return async_wrapper
            else:
                # Wrap sync function to be async
                @functools.wraps(func)
                async def sync_to_async_wrapper(*args, **kwargs):
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None, functools.partial(func, *args, **kwargs)
                    )
                    return await self._sign_result(tool_id, result)

                return sync_to_async_wrapper

        return decorator

    async def _execute_tool(
        self, tool_id: str, func: Callable, args: tuple, kwargs: dict
    ) -> SignedResponse:
        """Execute an async tool and sign the response."""
        try:
            result = await func(*args, **kwargs)
            return await self._sign_result(tool_id, result)
        except Exception as e:
            # Sign the error too for auditability
            error_data = {"error": str(e), "error_type": type(e).__name__}
            return await self._sign_result(tool_id, error_data)

    async def _sign_result(
        self,
        tool_id: str,
        result: Any,
        parent_signature: Optional[str] = None,
    ) -> SignedResponse:
        """Sign a result with optional parent chain link."""
        async with self._lock:
            nonce = None
            if self.config.enable_nonce:
                nonce = f"{time.time_ns()}-{id(self)}"

            response = self._signer.sign(
                tool_id=tool_id,
                data=result,
                nonce=nonce,
                parent_signature=parent_signature,
            )

            # Store for verification
            await asyncio.to_thread(
                self._storage.store, response.signature, response.to_dict()
            )

            return response

    async def sign(
        self,
        tool_id: str,
        data: Any,
        metadata: Optional[Dict[str, Any]] = None,
        parent_signature: Optional[str] = None,
    ) -> SignedResponse:
        """Sign data directly without using a tool decorator.

        Args:
            tool_id: Identifier for this signed data
            data: Data to sign
            metadata: Optional metadata to include
            parent_signature: Link to previous response in chain

        Returns:
            SignedResponse with cryptographic signature
        """
        if metadata:
            data = {"data": data, "metadata": metadata}

        return await self._sign_result(tool_id, data, parent_signature)

    async def verify(self, response: Union[SignedResponse, Dict[str, Any]]) -> bool:
        """Verify a signed response.

        Args:
            response: SignedResponse or dict to verify

        Returns:
            True if signature is valid

        Raises:
            NonceReplayError: If nonce was already used (replay attack)
        """
        if isinstance(response, dict):
            response = SignedResponse(**response)

        # Check nonce for replay protection
        if self.config.enable_nonce and self._nonce_storage and response.nonce:
            async with self._lock:
                is_new = await asyncio.to_thread(
                    self._nonce_storage.check_and_add, response.nonce
                )
                if not is_new:
                    from trustchain.utils.exceptions import NonceReplayError

                    raise NonceReplayError(f"Nonce already used: {response.nonce}")

        # Verify signature
        return self._signer.verify(response)

    async def verify_chain(self, responses: List[SignedResponse]) -> bool:
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

        for i, response in enumerate(responses):
            # Verify signature
            if not await self.verify(response):
                return False

            # Verify chain link (skip first)
            if i > 0:
                expected_parent = responses[i - 1].signature
                if response.parent_signature != expected_parent:
                    return False

        return True

    def session(
        self,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AsyncTrustChainSession":
        """Create an async session for automatic chain building.

        Args:
            session_id: Unique identifier for this session
            metadata: Optional metadata for all responses

        Returns:
            AsyncTrustChainSession async context manager

        Example:
            async with tc.session("user-123") as s:
                await s.sign("step1", {"query": "..."})
                await s.sign("step2", {"result": "..."})
                chain = s.get_chain()
        """
        return AsyncTrustChainSession(self, session_id, metadata)

    def export_public_key(self) -> str:
        """Export public key for external verification."""
        return self._signer.get_public_key()

    def get_key_id(self) -> str:
        """Get unique identifier for current signing key."""
        return self._signer.get_key_id()


class AsyncTrustChainSession:
    """Async session for building response chains.

    Automatically links responses with parent signatures.
    """

    def __init__(
        self,
        tc: AsyncTrustChain,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self._tc = tc
        self.session_id = session_id
        self.metadata = metadata or {}
        self._chain: List[SignedResponse] = []
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> "AsyncTrustChainSession":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    async def sign(
        self,
        tool_id: str,
        data: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SignedResponse:
        """Sign data and add to session chain.

        Automatically links to previous response.
        """
        async with self._lock:
            parent_sig = self._chain[-1].signature if self._chain else None

            merged_metadata = {**self.metadata, **(metadata or {})}
            merged_metadata["session_id"] = self.session_id

            response = await self._tc.sign(
                tool_id=tool_id,
                data=data,
                metadata=merged_metadata if merged_metadata else None,
                parent_signature=parent_sig,
            )

            self._chain.append(response)
            return response

    def get_chain(self) -> List[SignedResponse]:
        """Get the current response chain."""
        return list(self._chain)

    async def verify_chain(self) -> bool:
        """Verify the entire session chain."""
        return await self._tc.verify_chain(self._chain)

    def __len__(self) -> int:
        return len(self._chain)
