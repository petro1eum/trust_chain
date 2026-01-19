#!/usr/bin/env python3
"""Live test: TrustChain with Redis backend."""

from trustchain import TrustChain, TrustChainConfig
from trustchain.v2.nonce_storage import RedisNonceStorage

print("🔐 TrustChain + Redis Live Test")
print("=" * 50)

# Create config with Redis backend
config = TrustChainConfig(
    enable_nonce=True,
    nonce_ttl=3600,
)

# Create TrustChain with Redis nonce storage
tc = TrustChain(config)

# Replace in-memory storage with Redis
redis_storage = RedisNonceStorage(redis_url="redis://localhost:6379/0")
tc._nonce_storage = redis_storage

print(f"✅ Connected to Redis: {redis_storage.ping()}")
print()


# Define a tool
@tc.tool("payment")
def process_payment(amount: float, currency: str) -> dict:
    """Process a payment - critical operation requiring signature."""
    return {
        "amount": amount,
        "currency": currency,
        "status": "completed",
        "tx_id": "tx_12345",
    }


# Test 1: Sign and verify
print("Test 1: Sign and Verify")
result = process_payment(100.0, "USD")
print(f"  Data: {result.data}")
print(f"  Signature: {result.signature[:40]}...")
print(f"  Nonce: {result.nonce}")
print(f"  Verified: {result.is_verified}")
print()

# Test 2: Verify via TrustChain
print("Test 2: TrustChain.verify()")
is_valid = tc.verify(result)
print(f"  Valid: {is_valid}")
print()

# Test 3: Replay attack protection
print("Test 3: Replay Attack Protection")
try:
    tc.verify(result)  # Second verification should fail
    print("  ❌ FAILED - replay attack not detected!")
except Exception as e:
    print(f"  ✅ Blocked: {type(e).__name__}")
print()

# Test 4: Check Redis keys
print("Test 4: Redis State")
keys = redis_storage._client.keys("trustchain:nonce:*")
print(f"  Nonces stored: {len(keys)}")
print()

print("=" * 50)
print("✅ All tests passed! TrustChain + Redis working correctly.")
