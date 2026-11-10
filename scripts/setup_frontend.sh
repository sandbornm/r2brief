#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/web/frontend"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "[!] npm is required to install frontend dependencies. Install Node.js >=22.22.2." >&2
  exit 1
fi

# jsdom 30 requires Node ^22.22.2. Keep this floor in sync with package.json engines.
if ! node -e 'const [major, minor, patch] = process.versions.node.split(".").map(Number); if (!(major > 22 || (major === 22 && (minor > 22 || (minor === 22 && patch >= 2))))) process.exit(1)'; then
  echo "[!] Node.js $(node -v) is too old for the frontend. Install >=22.22.2." >&2
  exit 1
fi

echo "[*] Installing frontend dependencies"
cd "$FRONTEND_DIR"
npm ci

echo "[*] Building production bundle"
npm run typecheck
npm run build

echo "[*] Frontend setup complete (dist assets available at web/frontend/dist)"
