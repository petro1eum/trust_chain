"""Tests for AsyncTrustChain."""

import asyncio

import pytest

from trustchain import AsyncTrustChain, AsyncTrustChainSession, SignedResponse


class TestAsyncTrustChain:
    """Test async TrustChain functionality."""

    @pytest.mark.asyncio
    async def test_create_instance(self):
        """Test basic instance creation."""
        tc = AsyncTrustChain()
        assert tc is not None
        assert tc._signer is not None

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager."""
        async with AsyncTrustChain() as tc:
            assert tc is not None

    @pytest.mark.asyncio
    async def test_sign_basic(self):
        """Test basic signing."""
        async with AsyncTrustChain() as tc:
            result = await tc.sign("test_tool", {"value": 42})

            assert isinstance(result, SignedResponse)
            assert result.tool_id == "test_tool"
            assert result.data == {"value": 42}
            assert result.signature is not None

    @pytest.mark.asyncio
    async def test_verify_valid(self):
        """Test verification of valid signature."""
        async with AsyncTrustChain() as tc:
            result = await tc.sign("test", {"data": "test"})
            is_valid = await tc.verify(result)

            assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_invalid(self):
        """Test verification of tampered data."""
        async with AsyncTrustChain() as tc:
            result = await tc.sign("test", {"data": "original"})

            # Tamper with data
            result.data = {"data": "tampered"}

            is_valid = await tc.verify(result)
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_tool_decorator_async(self):
        """Test tool decorator with async function."""
        async with AsyncTrustChain() as tc:

            @tc.tool("async_tool")
            async def async_function(x: int) -> int:
                await asyncio.sleep(0.01)  # Simulate async work
                return x * 2

            result = await async_function(21)

            assert isinstance(result, SignedResponse)
            assert result.data == 42
            assert result.tool_id == "async_tool"

    @pytest.mark.asyncio
    async def test_chain_of_trust(self):
        """Test building a chain with parent signatures."""
        async with AsyncTrustChain() as tc:
            step1 = await tc.sign("step1", {"query": "test"})
            step2 = await tc.sign(
                "step2", {"result": "found"}, parent_signature=step1.signature
            )
            step3 = await tc.sign(
                "step3", {"output": "done"}, parent_signature=step2.signature
            )

            assert step2.parent_signature == step1.signature
            assert step3.parent_signature == step2.signature

    @pytest.mark.asyncio
    async def test_verify_chain(self):
        """Test chain verification."""
        async with AsyncTrustChain() as tc:
            step1 = await tc.sign("a", {})
            step2 = await tc.sign("b", {}, parent_signature=step1.signature)
            step3 = await tc.sign("c", {}, parent_signature=step2.signature)

            is_valid = await tc.verify_chain([step1, step2, step3])
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_chain_broken(self):
        """Test broken chain detection."""
        async with AsyncTrustChain() as tc:
            step1 = await tc.sign("a", {})
            step2 = await tc.sign("b", {})  # No parent link!
            step3 = await tc.sign("c", {}, parent_signature=step2.signature)

            is_valid = await tc.verify_chain([step1, step2, step3])
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_concurrent_signing(self):
        """Test concurrent async signing."""
        async with AsyncTrustChain() as tc:
            # Sign multiple items concurrently
            tasks = [tc.sign(f"tool_{i}", {"index": i}) for i in range(10)]

            results = await asyncio.gather(*tasks)

            assert len(results) == 10
            for i, result in enumerate(results):
                assert result.tool_id == f"tool_{i}"
                assert result.data == {"index": i}


class TestAsyncTrustChainSession:
    """Test async session functionality."""

    @pytest.mark.asyncio
    async def test_session_creation(self):
        """Test session creation."""
        async with AsyncTrustChain() as tc:
            session = tc.session("test-session")
            assert session is not None
            assert session.session_id == "test-session"

    @pytest.mark.asyncio
    async def test_session_context_manager(self):
        """Test session as context manager."""
        async with AsyncTrustChain() as tc:
            async with tc.session("test") as s:
                assert s is not None
                assert len(s) == 0

    @pytest.mark.asyncio
    async def test_session_auto_chain(self):
        """Test session auto-chains responses."""
        async with AsyncTrustChain() as tc:
            async with tc.session("user-123") as s:
                await s.sign("step1", {"input": "query"})
                await s.sign("step2", {"output": "result"})
                await s.sign("step3", {"final": "done"})

                chain = s.get_chain()

                assert len(chain) == 3
                assert chain[0].parent_signature is None
                assert chain[1].parent_signature == chain[0].signature
                assert chain[2].parent_signature == chain[1].signature

    @pytest.mark.asyncio
    async def test_session_verify_chain(self):
        """Test session chain verification."""
        async with AsyncTrustChain() as tc:
            async with tc.session("verify-test") as s:
                await s.sign("a", {})
                await s.sign("b", {})
                await s.sign("c", {})

                is_valid = await s.verify_chain()
                assert is_valid is True

    @pytest.mark.asyncio
    async def test_session_metadata(self):
        """Test session metadata is included."""
        async with AsyncTrustChain() as tc:
            async with tc.session("meta-test", metadata={"user": "alice"}) as s:
                result = await s.sign("action", {"value": 1})

                assert "metadata" in result.data
                assert result.data["metadata"]["session_id"] == "meta-test"
                assert result.data["metadata"]["user"] == "alice"


class TestAsyncKeys:
    """Test key operations."""

    @pytest.mark.asyncio
    async def test_export_public_key(self):
        """Test public key export."""
        async with AsyncTrustChain() as tc:
            pk = tc.export_public_key()
            assert pk is not None
            assert len(pk) > 0

    @pytest.mark.asyncio
    async def test_key_id(self):
        """Test key ID retrieval."""
        async with AsyncTrustChain() as tc:
            key_id = tc.get_key_id()
            assert key_id is not None
            assert len(key_id) == 36  # UUID format
