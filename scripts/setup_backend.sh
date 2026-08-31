#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON_VERSION="3.11"
INCLUDE_DEV=false

if [[ "${1:-}" == "--dev" ]]; then
  INCLUDE_DEV=true
  shift
fi
if [[ "$#" -ne 0 ]]; then
  echo "[!] Usage: scripts/setup_backend.sh [--dev]" >&2
  exit 2
fi

SYNC_SCOPE=(--no-dev)
if $INCLUDE_DEV; then
  SYNC_SCOPE=()
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "[!] uv is required. Install from https://github.com/astral-sh/uv (user-space)." >&2
  exit 1
fi

uv python install "$PYTHON_VERSION" >/dev/null 2>&1 || true

echo "[*] Synchronising backend base (repo-local .venv, no sudo)"
uv sync --locked --python "$PYTHON_VERSION" "${SYNC_SCOPE[@]}"

echo "[*] Resolving recommended extra"
SETUP_ARGS=(setup --json)
if [[ -n "${R2B_FLAVOR:-}" ]]; then
  SETUP_ARGS+=(--flavor "$R2B_FLAVOR")
fi
EXTRA="$({ uv run --no-sync --python "$PYTHON_VERSION" r2b "${SETUP_ARGS[@]}"; } | \
  uv run --no-sync --python "$PYTHON_VERSION" python -c \
    "import json,sys; print(json.load(sys.stdin)['uv_extra'])")"
echo "[*] Synchronising backend extra: $EXTRA"
uv sync --locked --python "$PYTHON_VERSION" --extra "$EXTRA" "${SYNC_SCOPE[@]}"

echo "[*] env"
uv run --no-sync --python "$PYTHON_VERSION" r2b env --json >/dev/null
echo "[*] Backend setup complete"
