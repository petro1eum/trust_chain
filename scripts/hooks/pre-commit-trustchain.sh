#!/usr/bin/env bash
# Block git commit when staged source files lack Ed25519 TrustChain proof.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

if [[ ! -f .apatch/enforcement.json ]] && [[ "${APATCH_ENFORCE:-}" != "1" ]]; then
  exit 0
fi

if ! command -v apatch >/dev/null 2>&1; then
  echo "pre-commit-trustchain: apatch not on PATH — commit blocked." >&2
  exit 1
fi

OUT="$(mktemp)"
ERR="$(mktemp)"
trap 'rm -f "$OUT" "$ERR"' EXIT

if ! apatch verify notarization --staged --target-dir "$ROOT" --json >"$OUT" 2>"$ERR"; then
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    p = d.get('rejection_prompt') or d.get('agent_prompt')
    if p:
        print(p, file=sys.stderr)
except Exception:
    pass
" "$OUT" 2>/dev/null || true
  fi
  cat "$ERR" >&2 2>/dev/null || true
  exit 1
fi
exit 0
