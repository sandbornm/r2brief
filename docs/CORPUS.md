# Benchmark corpus

The shipped manifest pins four inputs: NIST Juliet C/C++ 1.3, a sparse
checkout of Trail of Bits' native DARPA CGC port, and two OpenWrt firmware
releases around a known `ubusd` fix. Raw datasets stay outside Git.

```bash
python3 scripts/corpus_intake.py list
python3 scripts/corpus_intake.py fetch \
  openwrt-bpi-r3-mini-24.10.3 openwrt-bpi-r3-mini-24.10.4
python3 scripts/corpus_intake.py verify \
  openwrt-bpi-r3-mini-24.10.3 openwrt-bpi-r3-mini-24.10.4
```

`fetch` is the only command that opens the network. It accepts HTTPS from the
manifest's three hosts, refuses credentials in URLs, caps bytes, verifies
publisher SHA-256 values, and never unpacks or executes a download. The CGC
source is a no-prompt, no-hooks sparse checkout of one exact commit. Git's
transfer cap is checked after checkout, so run it in a quota-limited scratch
volume when a hard storage ceiling matters.

## Evidence chains

Juliet is a retrieval calibration set, not a realistic firmware set. Compile
matched good and bad variants with the same compiler, optimization, hardening,
and architecture. Keep the source case ID as ground truth. Measure whether a
top-k region leads to the labelled sink and whether `verify` finds the caller;
do not score an import name alone as a detected vulnerability. Start with the
manifest's seven memory, lifetime, arithmetic, null, and command-injection
CWEs, then stratify by flow variant and optimization level.

CGC supplies the harder middle tier. Its native port has patched and unpatched
binaries, POLLs for normal behavior, and POVs for the planted flaws. Build the
`Palindrome` and `basic_messaging` controls in a disposable Linux builder.
Compare the static brief and targeted decompilation across each pair. Run POLLs
or POVs only in a throwaway VM or container with no egress, no host mounts, a
non-root user, resource limits, and core dumps kept inside the scratch volume.
The ordinary r2b benchmark should remain static.

A local intake smoke on 2026-09-01 compiled Juliet's baseline CWE-121
`src_char_declare_cpy_01` into separate good-only and bad-only arm64 Mach-O
binaries with Apple clang 15 at `-O0`. Both produced the same two region types
and both had a dynamic `__strcpy_chk` caller. That is the expected negative
control: imports rank a place to inspect but cannot distinguish the labelled
good and bad cases. It also caught a command-fidelity defect, so generated r2
and `verify` commands now preserve fortified import names such as
`__strcpy_chk`.

The OpenWrt pair is the firmware tier. Verify both image hashes, inventory them
without extraction, then use `--extract` only where bubblewrap is available.
Hash every extracted child, match paths across releases, and analyze changed
ELFs rather than treating the wrapper as code. The existing
[`openwrt-ubusd-release-delta.json`](case-studies/openwrt-ubusd-release-delta.json)
links the image pair, selected child, call sites, decompilation, advisory, and
fix commit.

Report at least these measures:

- region recall at 1, 3, and 5;
- caller recall after `verify`;
- patched/unpatched ranking stability and changed-function localization;
- false leads from imports, strings, and signatures without caller/data flow;
- abstention when required tools or isolation are unavailable;
- elapsed time, peak stored bytes, tool versions, input hash, and replay argv.

Large vendor collections are useful for diversity and duplicate detection, but
not as primary truth sets. The neighboring Firmware-Dataset checkout can be
sampled locally by vendor, architecture, format, size, and exact SHA-256. Its
FTP-era URLs and redistribution terms vary, so do not mirror those binaries or
label them vulnerable without an advisory and a fixed comparison image.

## Safety boundary

`brief`, `verify`, and `decompile` are static wrappers. Firmware inventory no
longer carves files unless `--extract` is explicit. Extractors fail closed when
bubblewrap and its `--unshare-net` isolation are unavailable; the
`allow_unsafe_fallback` setting exists only for trusted inputs on an already
isolated host. Frida, GEF, and web script execution remain separate opt-ins.
