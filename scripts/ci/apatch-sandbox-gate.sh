#!/usr/bin/env bash
# Consumer CI gate: sandbox audit + TrustChain notarization (when configured).
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

if ! command -v apatch >/dev/null 2>&1; then
  echo "apatch-sandbox-gate: apatch not on PATH" >&2
  exit 1
fi

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

apatch sandbox ci-gate --target-dir "$ROOT" --json >"$OUT"

python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
if d.get('skipped'):
    print('apatch ci-gate: skipped (no sandbox/enforcement config)')
    sys.exit(0)
if not d.get('ok'):
    print(d.get('reason') or 'ci-gate failed', file=sys.stderr)
    p = d.get('notarization', {}).get('rejection_prompt') or d.get('notarization', {}).get('agent_message')
    if p:
        print(p, file=sys.stderr)
    sys.exit(1)
print('apatch ci-gate: passed')
" "$OUT"
