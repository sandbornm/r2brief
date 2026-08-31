#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/web/frontend"

if ! command -v npm >/dev/null 2>&1; then
  echo "[!] npm is required to install frontend dependencies. Install Node.js 20+." >&2
  exit 1
fi

echo "[*] Installing frontend dependencies"
cd "$FRONTEND_DIR"
npm ci

echo "[*] Building production bundle"
npm run typecheck
npm run build

echo "[*] Frontend setup complete (dist assets available at web/frontend/dist)"
