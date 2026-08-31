#!/usr/bin/env bash
# Regenerate samples/bin/arm64/vendor/ from this host's installed packages.
# The host is aarch64; binaries are gitignored (see .gitignore).
# Firmadyne images are mostly armel/mipsel; pull those manually from the
# firmadyne S3 bucket into samples/firmware/ if needed.
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
