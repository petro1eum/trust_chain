#!/bin/bash
# Quick script to format all code before committing
# Usage: ./scripts/format.sh

set -e

echo "🔧 Formatting code..."

# Run black
echo "  → black..."
if command -v uv >/dev/null 2>&1; then
    black trustchain/ tests/ examples/ 2>/dev/null || uv pip install black==24.8.0 && black trustchain/ tests/ examples/
else
    black trustchain/ tests/ examples/ 2>/dev/null || pip install black==24.8.0 && black trustchain/ tests/ examples/
fi

# Run isort  
echo "  → isort..."
isort trustchain/ tests/ examples/ --skip trustchain/core/__init__.py

# Run ruff fix (including notebooks)
echo "  → ruff --fix (py + ipynb)..."
if command -v uv >/dev/null 2>&1; then
    ruff check trustchain/ tests/ examples/ --fix --unsafe-fixes 2>/dev/null || uv pip install ruff && ruff check trustchain/ tests/ examples/ --fix --unsafe-fixes
else
    ruff check trustchain/ tests/ examples/ --fix --unsafe-fixes 2>/dev/null || pip install ruff && ruff check trustchain/ tests/ examples/ --fix --unsafe-fixes
fi

echo "✅ All formatting complete!"
echo ""
echo "Now run: git add -A && git commit -m 'your message' && git push"
