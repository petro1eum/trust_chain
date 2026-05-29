#!/bin/bash
# TrustChain YC Demo — Act 2, Part B: CLI (Git for AI)
#
# Pre-requisite: run yc_demo_setup.sh first to create the chain
# Then record this with asciinema or OBS
#
# Usage:
#   1. ./demo/yc_demo_cli_setup.sh   # creates .trustchain/ with 5 ops
#   2. ./demo/yc_demo_cli.sh         # the actual demo (record this)

set -e

DEMO_DIR="${YC_DEMO_DIR:-/tmp/yc-trustchain-demo}"
export TRUSTCHAIN_DIR="$DEMO_DIR/.trustchain"

echo ""
echo "──────────────────────────────────────────"
echo "  tc log — agent audit trail"
echo "──────────────────────────────────────────"
sleep 1
tc log -n 5
sleep 2

echo ""
echo "──────────────────────────────────────────"
echo "  tc blame code_executor — forensics"
echo "──────────────────────────────────────────"
sleep 1
tc blame code_executor
sleep 2

echo ""
echo "──────────────────────────────────────────"
echo "  tc revert — undo the dangerous action"
echo "──────────────────────────────────────────"
sleep 1
tc revert op_0003 -m "Agent executed rm -rf / — reverting"
sleep 2

echo ""
echo "──────────────────────────────────────────"
echo "  tc chain-verify — integrity check"
echo "──────────────────────────────────────────"
sleep 1
tc chain-verify
sleep 1

echo ""
echo "  ✅ Every action logged. Mistakes reverted."
echo "  ✅ Append-only chain — history can't be erased."
echo ""
