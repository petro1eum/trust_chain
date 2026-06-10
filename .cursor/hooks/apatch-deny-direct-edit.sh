#!/usr/bin/env bash
# Cursor preToolUse — block direct edits in apatch protected zones.
set -euo pipefail
ROOT="${CURSOR_PROJECT_DIR:-.}"
if command -v apatch >/dev/null 2>&1; then
  exec apatch sandbox hook-pre-tool --target-dir "$ROOT"
fi
if command -v python3 >/dev/null 2>&1; then
  exec python3 -m apatch.sandbox hook-pre-tool --target-dir "$ROOT"
fi
echo '{"permission":"allow"}'
