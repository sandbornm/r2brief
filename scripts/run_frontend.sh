#!/usr/bin/env bash
# run_frontend.sh - Start the r2b Vite frontend
set -euo pipefail

export LANG=C
export LC_ALL=C

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/web/frontend"
cd "$FRONTEND_DIR"

echo "╭──────────────────────────────────────╮"
echo "│  r2b Frontend · Vite dev on :5173    │"
echo "╰──────────────────────────────────────╯"

# Install deps if needed
if [[ ! -d "node_modules" ]]; then
    echo "Installing dependencies..."
    npm ci
fi

echo ""
echo "Starting frontend..."
exec npm run dev
