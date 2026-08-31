#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if ! command -v uv >/dev/null 2>&1; then
  echo "[!] uv not found. Run scripts/setup.sh first." >&2
  exit 1
fi

echo "[*] Performing environment check"
uv run scripts/detect_env.py --json > .dry_run_env.json

if [ -f samples/bin/arm64/hello ]; then
  echo "[*] Running quick analysis on samples/bin/arm64/hello"
  uv run r2b brief samples/bin/arm64/hello --quick --json > .dry_run_analysis.json || echo "[!] Analysis failed (expected if dependencies missing)"
else
  echo "[i] Place an ARM64 binary at samples/bin/arm64/hello to exercise the analysis pipeline"
fi

echo "[*] Artifacts written to .dry_run_env.json and .dry_run_analysis.json"
