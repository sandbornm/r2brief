# Debian GNU Hello, AArch64 calibration

This is a calibration sample, not a case study. GNU Hello is intentionally
trivial and benign. If a triage tool cannot stay modest here, the failure is
informative.

## Input and redistribution

| Field | Value |
|---|---|
| Package | Debian 13/trixie `hello` 2.10-5, arm64 |
| Upstream | [GNU Hello](https://www.gnu.org/software/hello/) |
| Immutable package | [Debian Snapshot](https://snapshot.debian.org/file/fecb242a059fec95f6cdc0760e9b44298c04d279/hello_2.10-5_arm64.deb) |
| Package index | [Debian arm64 metadata](https://packages.debian.org/trixie/arm64/hello/download) |
| Package size / SHA-256 | 52,660 bytes / `7a917c7f44fbd3373dff0f35a0b6bdf8ef564ff90579d8b130ff52fbf33fce1f` |
| Program license | GPL-3.0-or-later; [Debian copyright record](https://metadata.ftp-master.debian.org/changelogs/main/h/hello/hello_2.10-5_copyright) and [GNU licensing statement](https://www.gnu.org/software/hello/) |
| Extracted target | `usr/bin/hello` |
| Target size / SHA-256 | 68,232 bytes / `ef8b324e9d8de673554fb5dad0a69ffc9e6c20b93e92fd088745b3243aaad843` |
| Type | ELF64 AArch64 PIE, glibc interpreter `/lib/ld-linux-aarch64.so.1`, stripped |

The package is redistributable under GPLv3-or-later, but the repository does
not need a binary copy. The fetch script keeps source and license provenance
at the authoritative publisher and avoids permanent fixture weight.

## Extraction and run

These are the operations used; none invokes the AArch64 program:

```sh
mkdir -p /tmp/r2b-aarch64-cases/hello-pkg
cd /tmp/r2b-aarch64-cases/hello-pkg
ar x ../hello_2.10-5_arm64.deb
tar -xJf data.tar.xz

/usr/bin/time -p env R2B_IGNORE_LOCAL=1 \
  PYTHONPATH=/Users/michael/Github/r2brief/src \
  /Users/michael/Github/r2brief/.venv/bin/python -m r2b \
  brief ./usr/bin/hello --quick --no-save --json
```

Recorded output: [raw JSON](results/hello-aarch64-quick.json) and
[raw stderr/timing](results/hello-aarch64-quick.stderr.txt). The run took
1.74 s wall, 0.78 s user, and 0.31 s system. It preceded the uHTTPD run, so do
not treat their difference as a performance comparison.

## What r2b returned

- Correctly identified a 64-bit AArch64 Linux ELF and its entry at `0x1c00`.
- Reported 48 functions, 60 imports, `memcpy`, and a stripped target.
- Ranked entry disassembly first (score 89) and the `memcpy` import inventory
  second (score 78).
- Emitted one handoff:
  `r2b decompile /private/tmp/r2b-aarch64-cases/hello-pkg/usr/bin/hello 0x1c00 --json`.

All quick collection steps completed. Radare2 was marked `partial` because the
quick pass did not produce function/CFG evidence in the tool scorecard.
Capstone and DWARF were available but `not_run` because this was `--quick`.
Ghidra, angr, Frida, and GEF were disabled rather than attempted.

## Useful signal

The identity, architecture, interpreter, stripping state, entry address, and
replayable hash/recipe are useful setup facts. r2b also correctly avoids
claiming a verified caller or attacker-controlled argument. For a harness, the
output is a small deterministic capsule instead of several tool-specific blobs.

## Noise and limits

The `medium` risk label and “dangerous” `memcpy` region are unjustified as a
security conclusion for this known-benign program. Import presence alone is a
base-rate signal; `memcpy` is common and no call-site bounds or input control
were established. The generic “suspicious strings” factor is also not useful
here. Even the exact entry decompile handoff is low-value unless the analyst's
question concerns startup behavior.

That is the point of keeping this calibration sample: a veteran should read the
briefing as prioritization, not a verdict. The raw result shows where r2b
currently needs better negative evidence and calibration.
