#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT_DIR="$PROJECT_ROOT/ghidra/extensions/r2b"

if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
  echo "[!] Set GHIDRA_INSTALL_DIR to your Ghidra installation before running this script" >&2
  exit 1
fi

cd "$EXT_DIR"

if command -v gradle >/dev/null 2>&1; then
  GRADLE_CMD="gradle"
elif [ -x "${EXT_DIR}/gradlew" ]; then
  GRADLE_CMD="./gradlew"
else
  echo "[!] gradle not found. Install gradle or add a gradlew wrapper." >&2
  exit 1
fi

echo "[*] Building r2b Ghidra extension"
"$GRADLE_CMD" -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" build

echo "[*] Copying extension to user Ghidra directory"
OUTPUT_DIR="$PROJECT_ROOT/output/ghidra"
mkdir -p "$OUTPUT_DIR"
cp build/libs/r2b.zip "$OUTPUT_DIR"/r2b.zip

echo "[✓] Extension packaged at $OUTPUT_DIR/r2b.zip"
