#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/web/frontend"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "[!] npm is required to install frontend dependencies. Install Node.js ^22.22.2 || ^24.15.0 || >=26.0.0." >&2
  exit 1
fi

# jsdom 30 engines. scripts/frontend_node_range.mjs is the checker.
node "$PROJECT_ROOT/scripts/frontend_node_range.mjs"

echo "[*] Installing frontend dependencies"
cd "$FRONTEND_DIR"
npm ci

echo "[*] Building production bundle"
npm run typecheck
npm run build

echo "[*] Frontend setup complete (dist assets available at web/frontend/dist)"
