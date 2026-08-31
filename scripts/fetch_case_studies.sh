#!/usr/bin/env bash
set -euo pipefail

# Fetch the exact public AArch64 packages used by docs/case-studies and
# docs/calibration.
# This script only downloads and extracts; it never executes target code.

HELLO_URL="https://snapshot.debian.org/file/fecb242a059fec95f6cdc0760e9b44298c04d279/hello_2.10-5_arm64.deb"
HELLO_SHA256="7a917c7f44fbd3373dff0f35a0b6bdf8ef564ff90579d8b130ff52fbf33fce1f"
HELLO_BINARY_SHA256="ef8b324e9d8de673554fb5dad0a69ffc9e6c20b93e92fd088745b3243aaad843"
UHTTPD_URL="https://downloads.openwrt.org/releases/24.10.4/packages/aarch64_cortex-a53/base/uhttpd_2025.07.06~7e64e8ba-r5_aarch64_cortex-a53.ipk"
UHTTPD_SHA256="0a2d2858c81ec39c3d07048d9c79622602106b90d84a8534f112cd9ad883ab3f"
UHTTPD_BINARY_SHA256="2dea2e1017dd4839b375fff5a531b0d8c3317d8d031a3d44f0c2849cda1b0941"

OUTPUT_DIR="${1:-${TMPDIR:-/tmp}/r2b-case-studies}"
HELLO_DIR="$OUTPUT_DIR/hello"
UHTTPD_DIR="$OUTPUT_DIR/uhttpd"

for command in curl ar tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

mkdir -p "$HELLO_DIR" "$UHTTPD_DIR"

curl -fL --retry 3 --output "$OUTPUT_DIR/hello_2.10-5_arm64.deb" "$HELLO_URL"
curl -fL --retry 3 --output "$OUTPUT_DIR/uhttpd_2025.07.06~7e64e8ba-r5_aarch64_cortex-a53.ipk" "$UHTTPD_URL"

verify_sha256() {
  local expected="$1"
  local path="$2"
  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$path" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$path" | awk '{print $1}')"
  else
    echo "missing sha256sum or shasum" >&2
    exit 1
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "SHA-256 mismatch for $path: expected $expected, got $actual" >&2
    exit 1
  fi
}

verify_sha256 "$HELLO_SHA256" "$OUTPUT_DIR/hello_2.10-5_arm64.deb"
verify_sha256 "$UHTTPD_SHA256" "$OUTPUT_DIR/uhttpd_2025.07.06~7e64e8ba-r5_aarch64_cortex-a53.ipk"

(
  cd "$HELLO_DIR"
  ar x "$OUTPUT_DIR/hello_2.10-5_arm64.deb"
  tar -xJf data.tar.xz
)

(
  cd "$UHTTPD_DIR"
  tar -xzf "$OUTPUT_DIR/uhttpd_2025.07.06~7e64e8ba-r5_aarch64_cortex-a53.ipk"
  tar -xzf data.tar.gz
)

verify_sha256 "$HELLO_BINARY_SHA256" "$HELLO_DIR/usr/bin/hello"
verify_sha256 "$UHTTPD_BINARY_SHA256" "$UHTTPD_DIR/usr/sbin/uhttpd"

printf 'hello:  %s\n' "$HELLO_DIR/usr/bin/hello"
printf 'uhttpd: %s\n' "$UHTTPD_DIR/usr/sbin/uhttpd"
printf '\nAnalyze without persistence or execution:\n'
printf '  r2b brief %q --quick --no-save --json\n' "$HELLO_DIR/usr/bin/hello"
printf '  r2b brief %q --quick --no-save --json\n' "$UHTTPD_DIR/usr/sbin/uhttpd"
