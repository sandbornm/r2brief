#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "╭─────────────────────────────────────╮"
echo "│  r2b-web · Flask API on :5050       │"
echo "╰─────────────────────────────────────╯"

if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "✓ ANTHROPIC_API_KEY set"
else
    echo "⚠ ANTHROPIC_API_KEY not set"
fi

echo ""
echo "Starting backend..."
exec uv run r2b-web

