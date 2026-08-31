#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${1:-"$here/bin"}
src="$here/shallow.c"
mkdir -p "$out"

build_if_present() {
    compiler=$1
    name=$2
    shift 2
    if command -v "$compiler" >/dev/null 2>&1; then
        echo "build $name with $compiler"
        "$compiler" -O0 -fno-builtin-strcpy "$@" -o "$out/$name" "$src"
    else
        echo "skip $name: $compiler not found"
    fi
}

if command -v cc >/dev/null 2>&1; then
    build_if_present cc shallow-host
elif command -v clang >/dev/null 2>&1; then
    build_if_present clang shallow-host
else
    echo "skip shallow-host: no host C compiler found"
fi

build_if_present aarch64-linux-gnu-gcc shallow-linux-arm64
build_if_present arm-linux-gnueabihf-gcc shallow-linux-arm32
build_if_present x86_64-w64-mingw32-gcc shallow-windows-x86_64.exe

echo "outputs: $out"
