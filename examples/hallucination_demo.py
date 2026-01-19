#!/usr/bin/env python3
"""
TrustChain Demo: Hallucination vs Real Tool Call
=================================================

This demo shows why TrustChain matters:
- Without TrustChain: AI can invent any data (hallucination)
- With TrustChain: Only real tool calls produce valid signatures

Run: python examples/hallucination_demo.py
"""

from trustchain import TrustChain

# Initialize TrustChain
tc = TrustChain()


# =========================================
# REAL TOOL: Returns signed responses
# =========================================
@tc.tool("get_balance")
def get_real_balance(user_id: str) -> dict:
    """Simulate a real database call."""
    # This would be a real DB query in production
    return {"user_id": user_id, "balance": 1000.00, "currency": "USD"}


# =========================================
# SCENARIO 1: HALLUCINATED DATA
# =========================================
print("=" * 60)
print("❌ SCENARIO 1: AI HALLUCINATES DATA")
print("=" * 60)

# Imagine an AI model that just invents data without calling the tool
hallucinated_data = {
    "user_id": "user_123",
    "balance": 1000000.00,  # AI invented this number!
    "currency": "USD",
}

print(f"\nHallucinated response: {hallucinated_data}")
print(f"Type: {type(hallucinated_data).__name__}")
print("Has signature: ❌ No")
print("Can verify: ❌ No - IT'S JUST A DICT!")

# Try to verify - will fail because it's not a SignedResponse
try:
    tc.verify(hallucinated_data)
    print("Verified: ???")
except Exception as e:
    print(f"Verification error: {type(e).__name__}")

print("\n⚠️  Without TrustChain, you have NO WAY to know if this is real!")


# =========================================
# SCENARIO 2: REAL TOOL CALL
# =========================================
print("\n" + "=" * 60)
print("✅ SCENARIO 2: REAL TOOL CALL WITH TRUSTCHAIN")
print("=" * 60)

# Actually call the tool - returns SignedResponse
real_result = get_real_balance("user_123")

print(f"\nReal response data: {real_result.data}")
print(f"Type: {type(real_result).__name__}")
print("Has signature: ✅ Yes")
print(f"Signature: {real_result.signature[:40]}...")
print(f"Nonce: {real_result.nonce}")
print(f"Tool ID: {real_result.tool_id}")

# Verify the signature
is_valid = tc.verify(real_result)
print(f"\nVerification: {'✅ VALID' if is_valid else '❌ INVALID'}")

print("\n🔐 With TrustChain, EVERY real tool call is cryptographically signed!")


# =========================================
# SCENARIO 3: ATTACKER MODIFIES DATA
# =========================================
print("\n" + "=" * 60)
print("🚨 SCENARIO 3: ATTACKER TRIES TO MODIFY SIGNED DATA")
print("=" * 60)

# Get a real signed response
legit_response = get_real_balance("user_456")
print(f"\nOriginal data: {legit_response.data}")

# Attacker tries to modify the balance
from trustchain.v2.signer import SignedResponse

tampered_response = SignedResponse(
    data={"user_id": "user_456", "balance": 999999.99, "currency": "USD"},  # MODIFIED!
    signature=legit_response.signature,  # Same signature
    signature_id=legit_response.signature_id,
    timestamp=legit_response.timestamp,
    nonce=legit_response.nonce + "_tampered",  # Need different nonce to avoid replay
    tool_id=legit_response.tool_id,
)

print(f"Tampered data: {tampered_response.data}")

# Try to verify tampered data
try:
    is_valid = tc.verify(tampered_response)
    print(
        f"Verification: {'✅ VALID' if is_valid else '❌ INVALID - TAMPERING DETECTED!'}"
    )
except Exception as e:
    print(f"Verification failed: {e}")


# =========================================
# SUMMARY
# =========================================
print("\n" + "=" * 60)
print("📋 SUMMARY")
print("=" * 60)
print(
    """
| Scenario              | Has Signature | Verification |
|-----------------------|---------------|--------------|
| Hallucinated data     | ❌ No         | ❌ Fails     |
| Real tool call        | ✅ Yes        | ✅ Valid     |
| Tampered data         | ✅ Yes (old)  | ❌ Invalid   |

TrustChain makes AI hallucinations DETECTABLE.
If there's no valid signature, the data cannot be trusted.
"""
)
