#!/usr/bin/env python3
"""TrustChain YC Demo — compact script optimized for VHS terminal recording.

Shows: sign → verify → tamper → catch → revert.
Clean output, no warnings, large-font friendly.
"""
import copy
import os

# Suppress all warnings for clean demo output
os.environ["TRUSTCHAIN_CHAIN_STORAGE"] = "memory"
import warnings

warnings.filterwarnings("ignore")

from trustchain import TrustChain, TrustChainConfig

tc = TrustChain(
    config=TrustChainConfig(
        chain_storage="memory",
        enable_nonce=False,
    )
)

# ── Sign ──
print()
print("  \033[1;36m━━━ Step 1: Sign a tool response ━━━\033[0m")
print()
result = tc.sign(
    "bank_balance",
    {
        "account": "ACC-001",
        "balance": 42_000,
        "currency": "USD",
    },
)
print(f"  tool:      \033[1m{result.tool_id}\033[0m")
print(f"  data:      {result.data}")
print(f"  signature: \033[32m{result.signature[:44]}...\033[0m")

# ── Verify ──
print()
print(f"  \033[1;32m✅ tc.verify(result) → {tc.verify(result)}\033[0m")

# ── Tamper ──
print()
print("  \033[1;31m━━━ Step 2: Tamper with the data ━━━\033[0m")
print()
tampered = copy.deepcopy(result)
tampered.data["balance"] = 999_999
print(f"  original balance:  \033[32m{result.data['balance']:>10,}\033[0m")
print(f"  tampered balance:  \033[31m{tampered.data['balance']:>10,}\033[0m")
print()
print(f"  \033[1;31m❌ tc.verify(tampered) → {tc.verify(tampered)}\033[0m")
print("  \033[2m   Signature mismatch — forgery detected.\033[0m")

# ── Revert ──
print()
print("  \033[1;33m━━━ Step 3: Undo for AI ━━━\033[0m")
print()
op_id = tc.chain.log()[0]["id"]
tc.revert(op_id=op_id, reason="Suspicious activity")
v = tc.chain.verify()
print(f"  reverted:    \033[33m{op_id}\033[0m")
print(f"  chain valid: \033[32m{v['valid']}\033[0m")
print(f"  operations:  {tc.chain.length} (original + compensatory revert)")
print()
