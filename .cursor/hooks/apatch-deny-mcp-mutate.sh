#!/usr/bin/env bash
# Cursor beforeMCPExecution — whitelist apatch MCP tools under sandbox enforce.
set -euo pipefail
ROOT="${CURSOR_PROJECT_DIR:-.}"
if command -v apatch >/dev/null 2>&1; then
  exec apatch sandbox hook-pre-mcp --target-dir "$ROOT"
fi
if command -v python3 >/dev/null 2>&1; then
  exec python3 -m apatch.sandbox hook-pre-mcp --target-dir "$ROOT"
fi
echo '{"permission":"allow"}'
