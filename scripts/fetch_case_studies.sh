#!/usr/bin/env bash
set -euo pipefail

# Fetch the exact public AArch64 packages used by docs/case-studies and
# docs/calibration.
# This script only downloads and extracts; it never executes target code.

HELLO_URL="https://snapshot.debian.org/file/fecb242a059fec95f6cdc0760e9b44298c04d279/hello_2.10-5_arm64.deb"
HELLO_SHA256="7a917c7f44fbd3373dff0f35a0b6bdf8ef564ff90579d8b130ff52fbf33fce1f"
HELLO_BINARY_SHA256="ef8b324e9d8de673554fb5dad0a69ffc9e6c20b93e92fd088745b3243aaad843"
BUSYBOX_URL="https://downloads.openwrt.org/releases/24.10.4/packages/aarch64_cortex-a53/base/busybox_1.36.1-r3_aarch64_cortex-a53.ipk"
BUSYBOX_SHA256="3b6afb873a1325031ed04a2d35d96817fcbbaaa04e32e30962201ad2ffb05d77"
BUSYBOX_BINARY_SHA256="d3aeb34aaf9ff41d12db6345a811ee142890c6e071dcbcc1006b0fc02e90b66f"
DNSMASQ_URL="https://downloads.openwrt.org/releases/24.10.4/packages/aarch64_cortex-a53/base/dnsmasq_2.93-r1_aarch64_cortex-a53.ipk"
DNSMASQ_SHA256="6647ebdd4b7aa044f757c40801580891f9993799bea19d4f68a55be0da6ff7be"
DNSMASQ_BINARY_SHA256="a433c23caa56669d6d7ee2d896f157442941ab0ca6d37cc46f6bea6e43d84d7f"
UHTTPD_URL="https://downloads.openwrt.org/releases/24.10.4/packages/aarch64_cortex-a53/base/uhttpd_2025.07.06~7e64e8ba-r5_aarch64_cortex-a53.ipk"
UHTTPD_SHA256="0a2d2858c81ec39c3d07048d9c79622602106b90d84a8534f112cd9ad883ab3f"
UHTTPD_BINARY_SHA256="2dea2e1017dd4839b375fff5a531b0d8c3317d8d031a3d44f0c2849cda1b0941"
RPCD_URL="https://downloads.openwrt.org/releases/24.10.4/packages/aarch64_cortex-a53/base/rpcd_2025.09.01~bba95191-r2_aarch64_cortex-a53.ipk"
RPCD_SHA256="18a2dcbf0b0abe2a5d01e6e6b545b166dcde2116b4555f8ce694384d67b94fb6"
RPCD_BINARY_SHA256="ac6f18d11fe3d13ad5cd11ebf06861cb28b9464053351078020a7562ef9879ee"
UBUS_URL="https://downloads.openwrt.org/releases/24.10.4/packages/aarch64_cortex-a53/base/ubus_2025.10.17~60e04048-r1_aarch64_cortex-a53.ipk"
UBUS_SHA256="574f1380d2e58672b2c6ddd4e20e80f5d4103ad89c99760b65a3ef4d554db957"
UBUS_BINARY_SHA256="75196f1dfb03f2ea6a77f1f53608bbf1495d74613361a16e26587644f6072f8c"

OUTPUT_DIR="${1:-${TMPDIR:-/tmp}/r2b-case-studies}"
HELLO_DIR="$OUTPUT_DIR/hello"
BUSYBOX_DIR="$OUTPUT_DIR/busybox"
DNSMASQ_DIR="$OUTPUT_DIR/dnsmasq"
UHTTPD_DIR="$OUTPUT_DIR/uhttpd"
RPCD_DIR="$OUTPUT_DIR/rpcd"
UBUS_DIR="$OUTPUT_DIR/ubus"

for command in curl ar tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

mkdir -p "$HELLO_DIR" "$BUSYBOX_DIR" "$DNSMASQ_DIR" "$UHTTPD_DIR" "$RPCD_DIR" "$UBUS_DIR"

curl -fL --retry 3 --output "$OUTPUT_DIR/hello_2.10-5_arm64.deb" "$HELLO_URL"
curl -fL --retry 3 --output "$OUTPUT_DIR/busybox_1.36.1-r3_aarch64_cortex-a53.ipk" "$BUSYBOX_URL"
curl -fL --retry 3 --output "$OUTPUT_DIR/dnsmasq_2.93-r1_aarch64_cortex-a53.ipk" "$DNSMASQ_URL"
curl -fL --retry 3 --output "$OUTPUT_DIR/uhttpd_2025.07.06~7e64e8ba-r5_aarch64_cortex-a53.ipk" "$UHTTPD_URL"
curl -fL --retry 3 --output "$OUTPUT_DIR/rpcd_2025.09.01~bba95191-r2_aarch64_cortex-a53.ipk" "$RPCD_URL"
curl -fL --retry 3 --output "$OUTPUT_DIR/ubus_2025.10.17~60e04048-r1_aarch64_cortex-a53.ipk" "$UBUS_URL"

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
verify_sha256 "$BUSYBOX_SHA256" "$OUTPUT_DIR/busybox_1.36.1-r3_aarch64_cortex-a53.ipk"
verify_sha256 "$DNSMASQ_SHA256" "$OUTPUT_DIR/dnsmasq_2.93-r1_aarch64_cortex-a53.ipk"
verify_sha256 "$UHTTPD_SHA256" "$OUTPUT_DIR/uhttpd_2025.07.06~7e64e8ba-r5_aarch64_cortex-a53.ipk"
verify_sha256 "$RPCD_SHA256" "$OUTPUT_DIR/rpcd_2025.09.01~bba95191-r2_aarch64_cortex-a53.ipk"
verify_sha256 "$UBUS_SHA256" "$OUTPUT_DIR/ubus_2025.10.17~60e04048-r1_aarch64_cortex-a53.ipk"

(
  cd "$HELLO_DIR"
  ar x "$OUTPUT_DIR/hello_2.10-5_arm64.deb"
  tar -xJf data.tar.xz
)

(
  cd "$BUSYBOX_DIR"
  tar -xzf "$OUTPUT_DIR/busybox_1.36.1-r3_aarch64_cortex-a53.ipk"
  tar -xzf data.tar.gz
)

(
  cd "$DNSMASQ_DIR"
  tar -xzf "$OUTPUT_DIR/dnsmasq_2.93-r1_aarch64_cortex-a53.ipk"
  tar -xzf data.tar.gz
)

(
  cd "$UHTTPD_DIR"
  tar -xzf "$OUTPUT_DIR/uhttpd_2025.07.06~7e64e8ba-r5_aarch64_cortex-a53.ipk"
  tar -xzf data.tar.gz
)

(
  cd "$RPCD_DIR"
  tar -xzf "$OUTPUT_DIR/rpcd_2025.09.01~bba95191-r2_aarch64_cortex-a53.ipk"
  tar -xzf data.tar.gz
)

(
  cd "$UBUS_DIR"
  tar -xzf "$OUTPUT_DIR/ubus_2025.10.17~60e04048-r1_aarch64_cortex-a53.ipk"
  tar -xzf data.tar.gz
)

verify_sha256 "$HELLO_BINARY_SHA256" "$HELLO_DIR/usr/bin/hello"
verify_sha256 "$BUSYBOX_BINARY_SHA256" "$BUSYBOX_DIR/bin/busybox"
verify_sha256 "$DNSMASQ_BINARY_SHA256" "$DNSMASQ_DIR/usr/sbin/dnsmasq"
verify_sha256 "$UHTTPD_BINARY_SHA256" "$UHTTPD_DIR/usr/sbin/uhttpd"
verify_sha256 "$RPCD_BINARY_SHA256" "$RPCD_DIR/sbin/rpcd"
verify_sha256 "$UBUS_BINARY_SHA256" "$UBUS_DIR/bin/ubus"

printf 'hello:  %s\n' "$HELLO_DIR/usr/bin/hello"
printf 'busybox: %s\n' "$BUSYBOX_DIR/bin/busybox"
printf 'dnsmasq: %s\n' "$DNSMASQ_DIR/usr/sbin/dnsmasq"
printf 'uhttpd: %s\n' "$UHTTPD_DIR/usr/sbin/uhttpd"
printf 'rpcd: %s\n' "$RPCD_DIR/sbin/rpcd"
printf 'ubus: %s\n' "$UBUS_DIR/bin/ubus"
printf '\nAnalyze without persistence or execution:\n'
printf '  r2b brief %q --quick --no-save --json\n' "$HELLO_DIR/usr/bin/hello"
printf '  r2b brief %q --quick --no-save --json\n' "$BUSYBOX_DIR/bin/busybox"
printf '  r2b brief %q --quick --no-save --json\n' "$DNSMASQ_DIR/usr/sbin/dnsmasq"
printf '  r2b brief %q --quick --no-save --json\n' "$UHTTPD_DIR/usr/sbin/uhttpd"
printf '  r2b brief %q --quick --no-save --json\n' "$RPCD_DIR/sbin/rpcd"
printf '  r2b brief %q --quick --no-save --json\n' "$UBUS_DIR/bin/ubus"
