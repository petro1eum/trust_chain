#!/bin/bash
# Quick script to format all code before committing
# Usage: ./scripts/format.sh

set -e

echo "🔧 Formatting code..."

# Run black
echo "  → black..."
black trustchain/ tests/ examples/ 2>/dev/null || pip install black==24.8.0 && black trustchain/ tests/ examples/

# Run isort  
echo "  → isort..."
isort trustchain/ tests/ examples/ --skip trustchain/core/__init__.py

# Run ruff fix (including notebooks)
echo "  → ruff --fix (py + ipynb)..."
ruff check trustchain/ tests/ examples/ --fix --unsafe-fixes 2>/dev/null || pip install ruff && ruff check trustchain/ tests/ examples/ --fix --unsafe-fixes

echo "✅ All formatting complete!"
echo ""
echo "Now run: git add -A && git commit -m 'your message' && git push"
