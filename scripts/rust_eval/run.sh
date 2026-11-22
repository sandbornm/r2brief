#!/usr/bin/env bash
# Stripped-Rust eval: build fd-find for aarch64, derive truth from the
# symbolized twin, rank the stripped twins with `r2b brief --quick`, and score
# user-code p@5/p@10. Needs rustup + the aarch64 target, aarch64-linux-gnu
# gcc/binutils, and `uv sync --extra r2` plus rust-demangler in the venv.
# usage: run.sh <data-root> [summary.md]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
ROOT=$(mkdir -p "$1" && cd "$1" && pwd)
SUMMARY=${2:-}
TARGET=aarch64-unknown-linux-gnu
PROFILES="strip cargostrip"

"$HERE/build_fd.sh" "$ROOT"
cd "$REPO"
uv run --no-sync python "$HERE/truth.py" "$ROOT" "$TARGET" fd fd strip=sym cargostrip=cargostrip-sym
bins=()
for p in $PROFILES; do bins+=("bins/$TARGET/$p/fd"); done
status=0
uv run --no-sync python scripts/eval_ground_truth.py --data-root "$ROOT" \
  --r2b "$REPO/.venv/bin/r2b" --modes quick --nice 0 --out "$ROOT/results.json" "${bins[@]}" || status=$?
args=("$ROOT/results.json" "$HERE/baseline.json")
[ -n "$SUMMARY" ] && args+=(--summary "$SUMMARY")
uv run --no-sync python "$HERE/report.py" "${args[@]}" || status=1
exit $status
