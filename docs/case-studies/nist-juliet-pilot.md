# NIST Juliet retrieval slice: ranking is not a CWE detector

Status on 2026-09-02: **calibration recorded**. The machine-readable
result is [`nist-juliet-pilot.json`](nist-juliet-pilot.json). Raw zip,
sources, and ELFs stay in `.r2b-corpus`.

This is a retrieval check against labelled synthetic controls, not a
claim that r2b detects vulnerabilities. Juliet already names the CWE
and the sink. The product question is whether `--quick` ranking points
at that function, and whether `verify` finds a non-constant caller of
a libc sink when one exists.

## Frozen scope

Source: NIST Juliet C/C++ 1.3 zip
`2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip`, SHA-256
`ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`
(152,957,342 bytes). Intake: `python3 scripts/corpus_intake.py fetch`
then `verify` for `nist-juliet-c-cpp-1.3`. Unpacked only under
`.r2b-corpus/work/juliet/`.

Selection, frozen before scoring: one baseline flow variant per pinned
CWE. Prefer `*_01` / `src_char_declare_cpy_01`. Linux `char` / `system`
cases; no Win32, no sockets.

| CWE | Flow variant | Labelled sink function | libc sink |
|---|---|---|---|
| 121 | `src_char_declare_cpy_01` | `*_bad` / `goodG2B` | `strcpy` |
| 122 | `c_src_char_cpy_01` | `*_bad` / `goodG2B` | `strcpy` |
| 190 | `int_max_add_01` | `*_bad` / `goodG2B`+`goodB2G` | none (`data + 1`) |
| 415 | `malloc_free_char_01` | `*_bad` / `goodG2B`+`goodB2G` | `free` |
| 416 | `malloc_free_char_01` | `*_bad` / `goodG2B`+`goodB2G` | none (`printLine` after `free`) |
| 476 | `char_01` | `*_bad` / `goodG2B`+`goodB2G` | none (`data[0]`) |
| 78 | `char_console_system_01` | `*_bad` / `goodG2B` | `system` |

Compile (host gcc, this machine is aarch64):

```text
gcc -O0 -g -DINCLUDEMAIN -DOMITGOOD  -I testcasesupport -o BIN_bad  CASE.c io.c
gcc -O0 -g -DINCLUDEMAIN -DOMITBAD   -I testcasesupport -o BIN_good CASE.c io.c
```

All 14 outputs are ELF 64-bit LSB PIE, ARM aarch64, dynamically
linked, DWARF, not stripped. Not Mach-O. No compile abstentions.

Then, without following source-named functions:

```text
uv run r2b brief BIN --quick --no-save --json
uv run r2b verify BIN --import <labelled sink import> --json   # libc sink only
```

Scoring, also frozen:

- Region hit: a ranked region's subject is the labelled Juliet function
  (`*_bad`, `goodG2B`, `goodB2G`). `imports:*` listing a libc name is
  **not** a hit. `entry:main` is **not** a hit: the 12-line snippet is
  the INCLUDEMAIN prologue (`srand` / `printLine("Calling …")`), not
  the sink.
- `verify` caller hit: a non-constant call site whose function is that
  labelled sink function.
- If ranking / `verify` status match across good and bad, that is the
  expected negative control. Do not stretch `strcpy` presence into
  CWE-121.

Binaries were not executed. No POLLs, POVs, decompiles, or model calls.
`handoff.next_argv` was not changed: CWE-78 queued `r2b verify --import
system`; nobody auto-queued `decompile`.

## Result

Region recall at k=1, 3, and 5 is **0 / 14**. Every pair is identical.

`verify` caller recall is **8 / 8** of the binaries that have a labelled
libc sink, and **abstain** on CWE-190, CWE-416, and CWE-476. Those
hits are also identical across good and bad.

| CWE | var | regions | verify | region | caller | pair | brief s | verify s |
|---|---|---|---|---|---|---|---|---|
| 121 | bad | `entry:main`, `imports:memory` | `strcpy` dynamic @ `*_bad` | miss | hit | identical | 53.6 | 7.7 |
| 121 | good | `entry:main`, `imports:memory` | `strcpy` dynamic @ `goodG2B` | miss | hit | identical | 29.0 | 8.6 |
| 122 | bad | `entry:main`, `imports:memory` | `strcpy` dynamic @ `*_bad` | miss | hit | identical | 45.2 | 10.1 |
| 122 | good | `entry:main`, `imports:memory` | `strcpy` dynamic @ `goodG2B` | miss | hit | identical | 28.9 | 7.0 |
| 190 | bad | `entry:main` | abstain (no libc sink) | miss | — | identical | 24.4 | — |
| 190 | good | `entry:main` | abstain | miss | — | identical | 26.9 | — |
| 415 | bad | `entry:main` | `free` dynamic @ `*_bad` (noisy extra PLT xrefs) | miss | hit | identical | 26.6 | 7.0 |
| 415 | good | `entry:main` | `free` dynamic @ `goodG2B`/`goodB2G` (noisy) | miss | hit | identical | 40.2 | 7.2 |
| 416 | bad | `entry:main` | abstain (sink is `printLine`) | miss | — | identical | 25.3 | — |
| 416 | good | `entry:main` | abstain | miss | — | identical | 39.2 | — |
| 476 | bad | `entry:main` | abstain (sink is `data[0]`) | miss | — | identical | 27.1 | — |
| 476 | good | `entry:main` | abstain | miss | — | identical | 45.1 | — |
| 78 | bad | `imports:process`, `entry:main` | `system` mixed; real site dynamic @ `*_bad` | miss | hit | identical | 24.7 | 13.9 |
| 78 | good | `imports:process`, `entry:main` | `system` mixed; real site dynamic @ `goodG2B` | miss | hit | identical | 59.6 | 13.4 |

`imports:memory` is the string `strcpy`. `imports:process` is the
string `system`. That is the cheap PLT pivot the brief already
advertises, not retrieval of the labelled function.

CWE-78 is the only case that emits `next_argv`: `r2b verify … --import
system --json`. Following it finds a caller. It does not split good
from bad.

## What identical means here

Good-only and bad-only are compiled from the same file with
`OMITBAD` vs `OMITGOOD`. Both still call `strcpy` / `system` / `free`
(or neither, for 190/416/476). `--quick` therefore ranks the same
region ids. `verify` sees a stack buffer feeding the first argument
and reports `<dynamic>` on both sides. The good CWE-78 source is the
constant suffix `*.*` on `"ls "`; that did not resolve to
`all-constant`.

This is the expected negative control, same conclusion as the earlier
Darwin Mach-O smoke of CWE-121 (`__strcpy_chk` on both variants). The
Linux ELFs used plain `strcpy` at `-O0`; fortify did not rewrite the
import.

## Noise worth keeping

CWE-78 `verify` status is `mixed` because nearby string comments
(`"fgets() failed"`, `"command execution failed!"`) and an `imp.exit`
xref are attributed as extra `system` sites. The real call is
`<dynamic>` in the labelled function.

CWE-415 `verify --import free` includes extra `imp.malloc` /
`imp.exit` / `imp.free` sites around the same bytes. The labelled
function still appears. That is a noisy caller hit, not a double-free
finding. `free` is not a default `--quick` dangerous import, so the
brief never ranked it; `verify` was only run because the protocol
named the labelled sink import.

## Timing

Recorded on Kali Pi 5 (ARM64, 4 CPUs, 8 GiB) with r2b 0.1.0, radare2
6.0.5, file 5.47, gcc 15.3.0 (`aarch64-linux-gnu`), Python 3.11.13.
Tree: `ae6310c`. `--quick` only; Ghidra 12.1.2 is installed and was
not used.

| Mode | Wall |
|---|---|
| 14 sequential `brief --quick` | 495.9 s sum |
| 8 sequential `verify --import` | 74.9 s sum |

Per-binary briefs are 24.4–59.6 s. First CWE-121 bad brief paid a
cold-start tax (53.6 s). CWE-78 good is the slowest (59.6 s).

## Reproduce

```bash
python3 scripts/corpus_intake.py fetch nist-juliet-c-cpp-1.3
python3 scripts/corpus_intake.py verify nist-juliet-c-cpp-1.3

# unpack only the frozen *_01.c files plus C/testcasesupport
# into .r2b-corpus/work/juliet/

gcc -O0 -g -DINCLUDEMAIN -DOMITGOOD -I .r2b-corpus/work/juliet/C/testcasesupport \
  -o /tmp/juliet-bad CASE.c .r2b-corpus/work/juliet/C/testcasesupport/io.c

uv run r2b brief /tmp/juliet-bad --quick --no-save --json
uv run r2b verify /tmp/juliet-bad --import strcpy --json   # when a libc sink exists
```

Do not commit the zip, the unpacked tree, or the ELFs.

## Limits

- r2b did not discover these CWEs. Source already names them.
- Region recall is zero at every requested cutoff.
- Identical good/bad ranking is the recorded result on all seven pairs.
- `verify` locates a libc-sink caller when asked; it does not classify
  the labelled good source versus the labelled bad source.
- Import name alone is not a hit, and was not scored as one.
