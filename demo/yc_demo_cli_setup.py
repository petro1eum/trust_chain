#!/usr/bin/env python3
"""Setup script — creates a pre-populated .trustchain/ for CLI demo recording."""

import os
import shutil

from trustchain import TrustChain, TrustChainConfig

DEMO_DIR = os.environ.get("YC_DEMO_DIR", "/tmp/yc-trustchain-demo")
CHAIN_DIR = os.path.join(DEMO_DIR, ".trustchain")

# Clean slate
if os.path.exists(CHAIN_DIR):
    shutil.rmtree(CHAIN_DIR)

tc = TrustChain(
    config=TrustChainConfig(
        chain_storage="file",
        chain_dir=CHAIN_DIR,
    )
)

# Simulate a realistic agent session
tc.sign(
    "web_search",
    {
        "query": "NVIDIA Q2 2026 earnings",
        "result": "Revenue $44.1B, up 122% YoY",
    },
)
tc.sign(
    "bank_balance",
    {
        "account": "CORP-7291",
        "balance": 2_847_000,
        "currency": "USD",
    },
)
tc.sign(
    "code_executor",
    {
        "code": "rm -rf /",
        "status": "executed",
        "exit_code": 0,
    },
)
tc.sign(
    "email_send",
    {
        "to": "cfo@acme.com",
        "subject": "Wire Transfer Request",
        "body": "Please wire $50,000 to vendor account",
    },
)
tc.sign(
    "db_query",
    {
        "query": "UPDATE users SET role='admin' WHERE id=1337",
        "rows_affected": 1,
    },
)

print(f"✅ Demo chain created at: {CHAIN_DIR}")
print(f"   Operations: {tc.chain.length}")
print(f"   HEAD: {tc.chain.head()[:40]}...")
print("\n   Run the CLI demo:")
print(f"   export TRUSTCHAIN_DIR={CHAIN_DIR}")
print("   tc log")
