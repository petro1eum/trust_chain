"""Basic tests for TrustChain v2."""

import asyncio

import pytest

from trustchain.v2 import SignedResponse, TrustChain, TrustChainConfig


def test_basic_tool_creation():
    """Test creating and using a basic tool."""
    tc = TrustChain()

    @tc.tool("test_tool")
    def my_tool(x: int) -> dict:
        return {"result": x * 2}

    # Call the tool
    response = my_tool(5)

    # Check response
    assert isinstance(response, SignedResponse)
    assert response.tool_id == "test_tool"
    assert response.data == {"result": 10}
    assert response.signature is not None
    assert response.is_verified is True


def test_signed_response_is_not_implicitly_verified():
    """A manually constructed response must not appear verified."""
    response = SignedResponse(tool_id="x", data={"ok": True}, signature="junk")

    assert response.is_verified is False


def test_tool_verification():
    """Test signature verification."""
    # Disable nonce to test pure signature verification
    tc = TrustChain(TrustChainConfig(enable_nonce=False))

    @tc.tool("secure_tool")
    def secure_operation(value: str) -> dict:
        return {"value": value, "status": "processed"}

    # Execute tool
    response = secure_operation("test_data")

    # Verify signature
    assert tc.verify(response) is True

    # Create a tampered copy
    import copy

    tampered_response = copy.deepcopy(response)
    tampered_response.data["tampered"] = True

    # Verification should fail (signature doesn't match tampered data)
    assert tc.verify(tampered_response) is False


def test_nonce_replay_protection():
    """Test nonce-based replay protection."""
    tc = TrustChain(TrustChainConfig(enable_nonce=True))

    @tc.tool("protected_tool")
    def protected_op(x: int) -> int:
        return x + 1

    # First call
    response1 = protected_op(1)
    assert response1.nonce is not None

    # For this test, we'll check that nonces are unique across calls
    response2 = protected_op(2)
    assert response2.nonce is not None
    assert response1.nonce != response2.nonce

    # Both should verify successfully
    assert tc.verify(response1) is True
    assert tc.verify(response2) is True


def test_storage_and_caching():
    """Test response storage and caching."""
    tc = TrustChain(TrustChainConfig(enable_cache=True, max_cached_responses=2))

    @tc.tool("cached_tool")
    def get_data(key: str) -> str:
        return f"data_{key}"

    # Create multiple responses
    responses = []
    for i in range(3):
        responses.append(get_data(f"key{i}"))

    # Check cache size (should be limited to 2)
    stats = tc.get_stats()
    assert stats["cache_size"] <= 2


def test_tool_statistics():
    """Test tool execution statistics."""
    tc = TrustChain()

    @tc.tool("stats_tool")
    def process(x: int) -> int:
        if x < 0:
            raise ValueError("Negative input")
        return x * x

    # Multiple successful calls
    process(2)
    process(3)
    process(4)

    # One failed call
    with pytest.raises(ValueError):
        process(-1)

    # Check stats
    stats = tc.get_tool_stats("stats_tool")
    assert stats["call_count"] == 4  # Including failed call
    assert stats["last_error"] == "Negative input"
    assert stats["last_execution_time"] is not None


@pytest.mark.asyncio
async def test_async_tool():
    """Test async tool support."""
    tc = TrustChain()

    @tc.tool("async_tool")
    async def fetch_data(url: str) -> dict:
        await asyncio.sleep(0.01)  # Simulate async work
        return {"url": url, "fetched": True}

    # Call async tool
    response = await fetch_data("https://example.com")

    # Verify response
    assert isinstance(response, SignedResponse)
    assert response.data == {"url": "https://example.com", "fetched": True}
    assert response.is_verified is True


def test_config_validation():
    """Test configuration validation."""
    # Valid config
    config = TrustChainConfig(
        algorithm="ed25519", cache_ttl=3600, max_cached_responses=100
    )
    tc = TrustChain(config)
    assert tc.config.algorithm == "ed25519"

    # Invalid algorithm
    with pytest.raises(ValueError):
        TrustChainConfig(algorithm="invalid_algo")

    # Invalid cache settings
    with pytest.raises(ValueError):
        TrustChainConfig(cache_ttl=-1)

    with pytest.raises(ValueError):
        TrustChainConfig(max_cached_responses=0)


def test_multiple_tools():
    """Test multiple tools in same TrustChain."""
    tc = TrustChain()

    @tc.tool("tool1")
    def add(a: int, b: int) -> int:
        return a + b

    @tc.tool("tool2")
    def multiply(a: int, b: int) -> int:
        return a * b

    # Use both tools
    r1 = add(5, 3)
    r2 = multiply(4, 7)

    assert r1.data == 8
    assert r2.data == 28

    # Check overall stats
    stats = tc.get_stats()
    assert stats["total_tools"] == 2
    assert stats["total_calls"] == 2


def test_signed_response_serialization():
    """Test SignedResponse serialization."""
    tc = TrustChain()

    @tc.tool("serializable_tool")
    def get_info() -> dict:
        return {"info": "test", "number": 42}

    response = get_info()

    # Convert to dict
    response_dict = response.to_dict()

    # Should contain all required fields
    assert "tool_id" in response_dict
    assert "data" in response_dict
    assert "signature" in response_dict
    assert "signature_id" in response_dict
    assert "timestamp" in response_dict

    # Create new SignedResponse from dict
    new_response = SignedResponse(**response_dict)
    assert new_response.tool_id == response.tool_id
    assert new_response.data == response.data
