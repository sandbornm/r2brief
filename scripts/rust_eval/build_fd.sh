#!/usr/bin/env bash
# Build the pinned fd-find release for aarch64 Linux. Ranked variants:
#   strip      `aarch64-linux-gnu-strip --strip-all` on the `sym` build
#   cargostrip Cargo profile strip = "symbols"
# Truth twins (symbols kept, never ranked):
#   sym            release build with strip = "none"
#   cargostrip-sym strip = "symbols" profile, final link overridden with
#                  `-C strip=none`. The profile setting changes every crate's
#                  metadata hash and so the code layout; this twin keeps the
#                  same hashes as `cargostrip` and truth.py checks the bytes.
# usage: build_fd.sh <data-root>
set -euo pipefail

CRATE=fd-find
VERSION=10.5.2
SHA256=f7e6acb754467c87dddb589ea068a0b07249da8b99231fec1c329419c9cfc72e
TARGET=aarch64-unknown-linux-gnu
BIN=fd

ROOT=$(mkdir -p "$1" && cd "$1" && pwd)
SRC="$ROOT/src/$CRATE-$VERSION"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH=0

if [ ! -d "$SRC" ]; then
  mkdir -p "$ROOT/src"
  curl -sSfL --retry 3 -A "r2brief-ci (github.com/sandbornm/r2brief)" \
    -o "$ROOT/src/$CRATE-$VERSION.crate" \
    "https://static.crates.io/crates/$CRATE/$CRATE-$VERSION.crate"
  echo "$SHA256  $ROOT/src/$CRATE-$VERSION.crate" | sha256sum -c -
  tar xzf "$ROOT/src/$CRATE-$VERSION.crate" -C "$ROOT/src"
fi

build() {
  local profile=$1 strip=$2
  shift 2
  (cd "$SRC" && CARGO_PROFILE_RELEASE_STRIP=$strip CARGO_TARGET_DIR="$ROOT/target" \
    cargo "$@" --release --locked --target "$TARGET" --bin "$BIN" ${EXTRA:+-- $EXTRA})
  mkdir -p "$ROOT/bins/$TARGET/$profile"
  cp "$ROOT/target/$TARGET/release/$BIN" "$ROOT/bins/$TARGET/$profile/$BIN"
}

build sym none build
build cargostrip symbols build
EXTRA="-C strip=none" build cargostrip-sym symbols rustc
mkdir -p "$ROOT/bins/$TARGET/strip"
aarch64-linux-gnu-strip --strip-all -o "$ROOT/bins/$TARGET/strip/$BIN" "$ROOT/bins/$TARGET/sym/$BIN"
rustc -V
ls -l "$ROOT/bins/$TARGET"/*/"$BIN"
