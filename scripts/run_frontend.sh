#!/usr/bin/env bash
# run_frontend.sh - Start the r2b Vite frontend
set -euo pipefail

export LANG=C
export LC_ALL=C

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/web/frontend"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "[!] npm is required to install frontend dependencies. Install Node.js ^22.22.2 || ^24.15.0 || >=26.0.0." >&2
  exit 1
fi

node "$PROJECT_ROOT/scripts/frontend_node_range.mjs"

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
