# jq macOS arm64: Mach-O `--quick` stays thin without a process-launch import

Status on 2026-09-02: **thin-stop recorded**. The machine-readable result is
[`macho-jq.json`](macho-jq.json). The binary stays in
`.r2b-corpus/work/`.

This is a format-coverage check, not a CWE or malware claim. The product
question is whether `--quick` on a public Mach-O plus `verify` (only if a
process-launch import exists) produces a caller, or correctly stays thin.
The binary was **not executed**. `file(1)` and `r2b brief` on Linux are
the test.

## Frozen input

Official jq 1.8.2 macOS arm64 from the jqlang GitHub release:

| Field | Value |
|---|---|
| Release | [jq 1.8.2](https://github.com/jqlang/jq/releases/tag/jq-1.8.2) |
| Asset | [jq-macos-arm64](https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-macos-arm64) |
| Publisher SHA | [`sha256sum.txt`](https://github.com/jqlang/jq/releases/download/jq-1.8.2/sha256sum.txt) |
| Size / SHA-256 | 841,504 bytes / `2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e` |
| `file(1)` | Mach-O 64-bit arm64 executable, flags:`NOUNDEFS|DYLDLINK|TWOLEVEL|PIE|HAS_TLV_DESCRIPTORS` |
| License | MIT (jq); redistributable. Binary not committed. |

The SHA-256 matches the publisher `sha256sum.txt` line for
`jq-macos-arm64`.

## Protocol

```text
file BIN
uv run r2b brief BIN --quick --no-save --json
# only if subject.dangerous_imports includes system/popen/exec*:
uv run r2b verify BIN --import <name> --json
```

No model call. No decompile. `--quick` only. Do not run the Mach-O.

## Result

`--quick` identified a Mach-O, arm64/64, macOS, 400 functions, 135
imports. `dangerous_imports` is `__memcpy_chk`, `memcpy`, `memmove`,
`strcpy`. That is not `system` / `popen` / `exec*`, so `verify` was not
run. `interesting_imports` is empty.

Ranked regions:

| Rank | id | score | kind |
|---|---|---|---|
| 1 | `entry:entry` | 89 | disasm @ `0x1000008a8` (`main`) |
| 2 | `imports:memory` | 84 | inventory (`__memcpy_chk`/`memmove`/`strcpy`) |

`handoff.next_argv` is `[]`. It does not contain `decompile`.

Fortified `memcpy`/`strcpy` names are pivots, not callers and not a
vulnerability.

## Timing

Recorded on Kali Pi 5 (ARM64, 4 CPUs, 8 GiB) with r2b 0.1.0, radare2
6.0.5, file 5.47, Python 3.11.13. Tree: `2bfe565`. `--quick` only;
Ghidra 12.1.2 is installed and was not used.

| Mode | Wall |
|---|---|
| `brief --quick` | 39.778 s |
| `verify` | not run |

GNU time is absent on this host; wall time is `perf_counter` around the
CLI.

## Reproduce

```bash
curl -L -o jq-macos-arm64 \
  https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-macos-arm64
# SHA-256 2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e

file jq-macos-arm64
uv run r2b brief jq-macos-arm64 --quick --no-save --json
```

Do not execute `jq-macos-arm64`. Do not commit the Mach-O.

## Limits

- r2b did not claim a bug in jq.
- `verify` correctly stayed off: no process-launch import.
- `__memcpy_chk` inventory is not a memory-corruption finding.
- Linux cannot run this Darwin binary; that was never the test.
