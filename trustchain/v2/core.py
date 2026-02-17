"""Core TrustChain v2 implementation."""

import asyncio
import base64
import functools
import json
import os
import time
from typing import Any, Callable, Dict, Optional, Union

from trustchain.utils.exceptions import NonceReplayError

from .chain_store import ChainStore
from .config import TrustChainConfig
from .metrics import get_metrics
from .nonce_storage import NonceStorage, create_nonce_storage
from .signer import SignedResponse, Signer
from .storage import FileStorage, MemoryStorage, Storage
from .verifiable_log import VerifiableChainStore
from .x509_pki import AgentCertificate, TrustChainCA

# Sentinel: distinguishes "auto-chain from HEAD" (default) from
# "explicitly no parent" (None, e.g. first step in a session).
_UNSET = object()


class TrustChain:
    """Simple API for cryptographically signed tool responses."""

    def __init__(self, config: Optional[TrustChainConfig] = None):
        """Initialize TrustChain with optional configuration."""
        self.config = config or TrustChainConfig()
        self._signer = self._load_or_create_signer()
        self._storage = self._create_storage()
        self._tools: Dict[str, Dict[str, Any]] = {}

        # Git-like chain persistence
        self.chain: ChainStore = self._create_chain_store()

        # X.509 PKI: bootstrap CA hierarchy + issue agent cert
        self._root_ca: Optional[TrustChainCA] = None
        self._intermediate_ca: Optional[TrustChainCA] = None
        self._agent_cert: Optional[AgentCertificate] = None
        if self.config.enable_pki:
            self._bootstrap_pki()

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
        elif self.config.storage_backend == "file":
            return FileStorage(self.config.chain_dir)
        else:
            raise ValueError(f"Unknown storage backend: {self.config.storage_backend}")

    def _create_chain_store(self) -> ChainStore:
        """Create the Git-like chain store for persistent audit trail."""
        if not self.config.enable_chain:
            # Disabled — use in-memory only, no persistence
            return ChainStore(MemoryStorage(max_size=10000))

        if self.config.chain_storage == "verifiable":
            # Certificate Transparency-style: chain.log + Merkle tree + SQLite index
            vlog = VerifiableChainStore(self.config.chain_dir)
            return ChainStore(
                MemoryStorage(max_size=10000),
                root_dir=self.config.chain_dir,
                verifiable_log=vlog,
            )
        elif self.config.chain_storage == "memory":
            return ChainStore(MemoryStorage(max_size=10000))
        elif self.config.chain_storage == "file":
            chain_storage = FileStorage(self.config.chain_dir)
            return ChainStore(chain_storage, root_dir=self.config.chain_dir)
        elif self.config.chain_storage == "sqlite":
            # Pro feature — import dynamically
            try:
                from trustchain_pro.enterprise.sqlite_store import SQLiteChainStore

                return ChainStore(
                    SQLiteChainStore(db_path=f"{self.config.chain_dir}/chain.db"),
                    root_dir=self.config.chain_dir,
                )
            except ImportError:
                # Fallback to file if Pro not available
                chain_storage = FileStorage(self.config.chain_dir)
                return ChainStore(chain_storage, root_dir=self.config.chain_dir)
        else:
            raise ValueError(f"Unknown chain_storage: {self.config.chain_storage}")

    # ── X.509 PKI ──

    def _bootstrap_pki(self) -> None:
        """Bootstrap X.509 PKI hierarchy.

        On first run:
          1. Creates Root CA → saves to ~/.trustchain/pki/
          2. Creates Intermediate CA → saves to ~/.trustchain/pki/

        On every run:
          3. Loads Root + Intermediate from disk
          4. Issues a short-lived agent cert (1hr default)

        This gives every TrustChain instance a verifiable X.509 identity.
        """
        import uuid
        from pathlib import Path

        pki_dir = Path(self.config.chain_dir).expanduser().resolve() / "pki"
        pki_dir.mkdir(parents=True, exist_ok=True)

        root_cert_path = pki_dir / "trustchain_root_ca.crt"
        root_key_path = pki_dir / "trustchain_root_ca.key"
        int_cert_path = pki_dir / "trustchain_platform_ca.crt"
        int_key_path = pki_dir / "trustchain_platform_ca.key"

        org = self.config.pki_organization

        # 1. Root CA — create or load
        if root_cert_path.exists() and root_key_path.exists():
            self._root_ca = TrustChainCA.load(str(pki_dir), "TrustChain Root CA")
        else:
            self._root_ca = TrustChainCA.create_root_ca(
                name="TrustChain Root CA",
                organization=org,
            )
            self._root_ca.save(str(pki_dir))

        # 2. Intermediate CA — create or load
        if int_cert_path.exists() and int_key_path.exists():
            self._intermediate_ca = TrustChainCA.load(
                str(pki_dir), "TrustChain Platform CA"
            )
        else:
            self._intermediate_ca = self._root_ca.issue_intermediate_ca(
                name="TrustChain Platform CA",
                organization=org,
            )
            self._intermediate_ca.save(str(pki_dir))

        # 3. Issue short-lived agent cert for this session
        agent_id = self.config.pki_agent_id or f"agent-{uuid.uuid4().hex[:8]}"
        self._agent_cert = self._intermediate_ca.issue_agent_cert(
            agent_id=agent_id,
            model_hash="",  # User can set via config
            prompt_hash="",
            validity_hours=self.config.pki_validity_hours,
            organization=org,
        )

    @property
    def agent_cert(self) -> Optional[AgentCertificate]:
        """X.509 certificate for this agent instance (short-lived)."""
        return self._agent_cert

    @property
    def pki_root_ca(self) -> Optional[TrustChainCA]:
        """Root CA of the PKI hierarchy."""
        return self._root_ca

    @property
    def pki_intermediate_ca(self) -> Optional[TrustChainCA]:
        """Intermediate CA that issues agent certificates."""
        return self._intermediate_ca

    def issue_agent_cert(
        self,
        agent_id: str,
        model_hash: str = "",
        prompt_hash: str = "",
        tool_versions: Optional[Dict[str, str]] = None,
        capabilities: Optional[list] = None,
        validity_hours: Optional[int] = None,
    ) -> AgentCertificate:
        """Issue a new agent certificate from the Intermediate CA.

        Use this to issue certs for other agents or services.

        Args:
            agent_id: Unique identifier (becomes X.509 CN)
            model_hash: SHA-256 of the AI model
            prompt_hash: SHA-256 of the system prompt
            tool_versions: Dict of tool name -> version
            capabilities: List of allowed capabilities
            validity_hours: Cert validity (default from config)

        Returns:
            AgentCertificate with private key for signing
        """
        if not self._intermediate_ca:
            raise RuntimeError(
                "PKI not enabled. Set enable_pki=True in TrustChainConfig."
            )
        return self._intermediate_ca.issue_agent_cert(
            agent_id=agent_id,
            model_hash=model_hash,
            prompt_hash=prompt_hash,
            tool_versions=tool_versions,
            capabilities=capabilities,
            validity_hours=validity_hours or self.config.pki_validity_hours,
            organization=self.config.pki_organization,
        )

    def spawn_sub_agent(
        self,
        agent_id: str,
        model_hash: str = "",
        prompt_hash: str = "",
        tool_versions: Optional[Dict[str, str]] = None,
        capabilities: Optional[list] = None,
        validity_hours: Optional[int] = None,
    ) -> AgentCertificate:
        """Spawn a sub-agent with B+ delegated trust.

        The Platform CA issues a cert for the sub-agent with
        parent_cert_serial OID pointing to this agent's cert.
        The main agent NEVER gets CA=TRUE — only the Platform CA
        can issue certificates (SPIFFE-style).

        Cascading revocation: if this agent is revoked, all sub-agents
        automatically fail verification (PARENT_REVOKED).

        Args:
            agent_id: Sub-agent identifier
            model_hash: Hash of sub-agent's model
            prompt_hash: Hash of sub-agent's prompt
            tool_versions: Sub-agent's tools
            capabilities: Sub-agent's allowed capabilities
            validity_hours: Cert validity (default from config)

        Returns:
            AgentCertificate for the sub-agent
        """
        if not self._intermediate_ca:
            raise RuntimeError("PKI not enabled.")
        if not self._agent_cert:
            raise RuntimeError("No agent cert — cannot spawn sub-agent.")

        return self._intermediate_ca.issue_agent_cert(
            agent_id=agent_id,
            model_hash=model_hash,
            prompt_hash=prompt_hash,
            tool_versions=tool_versions,
            capabilities=capabilities,
            validity_hours=validity_hours or self.config.pki_validity_hours,
            organization=self.config.pki_organization,
            parent_serial=self._agent_cert.serial_number,
        )

    def revoke_agent(self, cert: AgentCertificate, reason: str = "revoked") -> None:
        """Revoke an agent certificate (red button).

        After revocation, the agent cert will fail verification.
        B+ cascading: all sub-agents of this agent also become invalid.
        """
        if not self._intermediate_ca:
            raise RuntimeError("PKI not enabled.")
        self._intermediate_ca.revoke(cert.serial_number, reason)

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

    def sign(
        self,
        tool_id: str,
        data: Any,
        metadata: Optional[Dict[str, Any]] = None,
        parent_signature=_UNSET,
        latency_ms: float = 0,
        session_id: Optional[str] = None,
    ) -> SignedResponse:
        """Sign data directly without using a tool decorator.

        Automatically commits to the chain if enable_chain is True.

        parent_signature behaviour:
          - _UNSET (default): auto-chain from chain HEAD
          - None: explicitly no parent (first step in a session)
          - str: use this exact parent signature

        Args:
            tool_id: Identifier for this signed data
            data: Data to sign
            metadata: Optional metadata to include
            parent_signature: Parent signature for chaining. Omit for
                auto-chaining, pass None for no parent.
            latency_ms: Tool execution latency (for analytics)
            session_id: Session ID for ref tracking

        Returns:
            SignedResponse with cryptographic signature
        """
        # Auto-chain: use chain HEAD only if parent was not specified at all
        if parent_signature is _UNSET:
            if self.config.enable_chain:
                parent_signature = self.chain.parent_signature()
            else:
                parent_signature = None

        # Generate nonce if enabled
        nonce = None
        if self.config.enable_nonce:
            nonce = self._generate_nonce()

        # Sign the response with certificate if configured
        signed = self._signer.sign(tool_id, data, nonce, parent_signature)

        # Add certificate from config if present
        if self.config.certificate:
            signed.certificate = self.config.certificate

        # Auto-commit to chain (like `git commit -a`)
        if self.config.enable_chain:
            self.chain.commit(
                tool=tool_id,
                data=data if isinstance(data, dict) else {"value": data},
                signature=signed.signature,
                signature_id=signed.signature_id,
                nonce=signed.nonce,
                parent_signature=signed.parent_signature,
                key_id=self._signer.get_key_id(),
                algorithm=self.config.algorithm,
                latency_ms=latency_ms,
                session_id=session_id,
                metadata=metadata,
            )

        return signed

    def session(
        self,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Create a session for automatic chain building.

        Args:
            session_id: Unique identifier for this session
            metadata: Optional metadata for all responses in session

        Returns:
            TrustChainSession context manager

        Example:
            async with tc.session("agent_123") as s:
                s.sign("step1", {"query": "..."})
                s.sign("step2", {"result": "..."})
                chain = s.get_chain()
        """
        from .session import TrustChainSession

        return TrustChainSession(self, session_id, metadata)

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

    def rotate_keys(self, save: bool = True) -> str:
        """Rotate to new signing keys.

        Generates a new key pair, invalidating all previous signatures.

        Args:
            save: If True and key_file is configured, save new keys to file.

        Returns:
            New key ID
        """
        # Create new signer with fresh keys
        self._signer = Signer(algorithm=self.config.algorithm)

        # Save if configured
        if save and self.config.key_file:
            self.save_keys()

        return self._signer.get_key_id()

    # === Marketing-Friendly Class Decorator ===

    def dehallucinate(self, cls: type = None, *, exclude: list = None):
        """
        Decorator to make an entire class 'hallucination-proof'.

        All public methods (not starting with _) will automatically
        return cryptographically signed responses.

        Example:
            @tc.dehallucinate
            class MyAgentTools:
                def search_database(self, query: str) -> dict:
                    return {"results": [...]}

                def call_api(self, endpoint: str) -> dict:
                    return requests.get(endpoint).json()

            # All methods now return SignedResponse!
            tools = MyAgentTools()
            result = tools.search_database("test")
            assert tc.verify(result)  # True - this is real data!

        Args:
            cls: Class to wrap (used when decorator is @tc.dehallucinate)
            exclude: List of method names to skip (e.g., ['helper_method'])

        Returns:
            Wrapped class with all public methods signed
        """
        exclude_set = set(exclude or [])

        def wrap_class(cls: type) -> type:
            import inspect

            for name in dir(cls):
                # Skip private/magic methods
                if name.startswith("_"):
                    continue

                # Skip excluded methods
                if name in exclude_set:
                    continue

                method = getattr(cls, name)

                # Only wrap callable methods
                if not callable(method) or isinstance(method, type):
                    continue

                # Skip class methods and static methods for now
                if isinstance(
                    inspect.getattr_static(cls, name), (classmethod, staticmethod)
                ):
                    continue

                # Create tool_id from class.method
                tool_id = f"{cls.__name__}.{name}"

                # Wrap the method
                wrapped = self.tool(tool_id)(method)
                setattr(cls, name, wrapped)

            # Mark class as dehallucinated
            cls._trustchain_dehallucinated = True
            cls._trustchain_instance = self

            return cls

        # Support both @tc.dehallucinate and @tc.dehallucinate()
        if cls is not None:
            return wrap_class(cls)
        return wrap_class
