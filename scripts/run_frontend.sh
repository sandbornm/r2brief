#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/web/frontend"
cd "$FRONTEND_DIR"

echo "╭──────────────────────────────────────╮"
echo "│  r2b Frontend · Vite dev on :5173    │"
echo "╰──────────────────────────────────────╯"

if [[ ! -d "node_modules" ]]; then
    echo "Installing dependencies..."
    npm ci
fi

echo ""
echo "Starting frontend..."
exec npm run dev
