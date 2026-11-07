#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=samples/bin/arm64/vendor
mkdir -p "$OUT"

for src in /usr/bin/openssl /usr/sbin/sshd /usr/bin/curl /usr/bin/wget \
           /usr/bin/find /usr/bin/xargs /usr/bin/busybox /usr/bin/tcpdump; do
    [ -x "$src" ] || { echo "skip (missing): $src" >&2; continue; }
    cp -p "$src" "$OUT/$(basename "$src")"
done

echo "vendor samples refreshed under $OUT"
