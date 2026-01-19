"""Tests for async tools and coroutines."""

import asyncio

import pytest

from trustchain import TrustChain
from trustchain.v2.signer import SignedResponse


class TestAsyncTools:
    """Test async tool execution."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    @pytest.mark.asyncio
    async def test_async_tool_basic(self, tc):
        @tc.tool("async_hello")
        async def async_hello(name: str) -> str:
            await asyncio.sleep(0.01)
            return f"Hello, {name}"

        result = await async_hello("World")

        assert isinstance(result, SignedResponse)
        assert result.data == "Hello, World"
        assert result.signature is not None

    @pytest.mark.asyncio
    async def test_async_tool_returns_dict(self, tc):
        @tc.tool("async_weather")
        async def async_weather(city: str) -> dict:
            await asyncio.sleep(0.01)
            return {"city": city, "temp": 22}

        result = await async_weather("Moscow")

        assert result.data["city"] == "Moscow"
        assert result.data["temp"] == 22

    @pytest.mark.asyncio
    async def test_async_tool_signature_verifies(self, tc):
        @tc.tool("async_calc")
        async def async_add(a: int, b: int) -> int:
            return a + b

        result = await async_add(2, 3)

        assert tc._signer.verify(result) is True

    @pytest.mark.asyncio
    async def test_multiple_async_calls(self, tc):
        @tc.tool("async_counter")
        async def async_counter(n: int) -> int:
            await asyncio.sleep(0.001)
            return n * 2

        # Run multiple async calls concurrently
        tasks = [async_counter(i) for i in range(10)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 10
        for i, result in enumerate(results):
            assert result.data == i * 2

    @pytest.mark.asyncio
    async def test_async_tool_exception(self, tc):
        @tc.tool("async_error")
        async def async_error() -> str:
            raise ValueError("Async error occurred")

        with pytest.raises(ValueError, match="Async error occurred"):
            await async_error()


class TestMixedSyncAsync:
    """Test mixing sync and async tools."""

    @pytest.fixture
    def tc(self):
        return TrustChain()

    @pytest.mark.asyncio
    async def test_sync_and_async_together(self, tc):
        @tc.tool("sync_tool")
        def sync_add(a: int, b: int) -> int:
            return a + b

        @tc.tool("async_tool")
        async def async_multiply(a: int, b: int) -> int:
            return a * b

        # Sync call
        sync_result = sync_add(2, 3)

        # Async call
        async_result = await async_multiply(2, 3)

        assert sync_result.data == 5
        assert async_result.data == 6

    @pytest.mark.asyncio
    async def test_async_chain_of_trust(self, tc):
        @tc.tool("async_step")
        async def async_step(value: int) -> int:
            await asyncio.sleep(0.001)
            return value * 2

        # Build async chain
        step1 = await async_step(1)
        step2 = tc._signer.sign(
            "step2", {"value": step1.data * 2}, parent_signature=step1.signature
        )
        step3 = tc._signer.sign(
            "step3",
            {"value": step2.data["value"] * 2},
            parent_signature=step2.signature,
        )

        # Verify chain
        chain = [step1, step2, step3]
        assert tc.verify_chain(chain) is True
