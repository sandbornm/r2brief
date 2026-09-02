# Windows curl.exe: PE `--quick` stays thin without a process-launch import

Status on 2026-09-02: **thin-stop recorded**. The machine-readable result is
[`pe-curl-win64.json`](pe-curl-win64.json). The zip and `curl.exe` stay in
`.r2b-corpus/work/`.

This is a format-coverage check, not a CWE or malware claim. The product
question is whether `--quick` on a public PE plus `verify` (only if a
process-launch import exists) produces a caller, or correctly stays thin.

## Frozen input

Official curl 8.22.0 for Windows x64 (`8.22.0_1` win64-mingw). The
`curl/curl` GitHub release
[`curl-8_22_0`](https://github.com/curl/curl/releases/tag/curl-8_22_0)
attaches source archives only:

```text
https://github.com/curl/curl/releases/download/curl-8_22_0/curl-8.22.0-win64-mingw.zip
HTTP 404
```

The frozen win64-mingw zip is the official curl-for-win package:

| Field | Value |
|---|---|
| Package | [curl 8.22.0_1 win64-mingw](https://curl.se/windows/dl-8.22.0_1/curl-8.22.0_1-win64-mingw.zip) |
| Publisher SHA | [`.zip.txt`](https://curl.se/windows/dl-8.22.0_1/curl-8.22.0_1-win64-mingw.zip.txt) |
| Zip size / SHA-256 | 8,691,604 bytes / `7f23b039f6ea4197362d4468e1a0e71428201222e1bef3b680d5ef7b2aefb714` |
| Extracted member | `curl-8.22.0_1-win64-mingw/bin/curl.exe` only |
| `curl.exe` size / SHA-256 | 3,882,088 bytes / `57309336350df718d9d3f76694d86a997bf9dc6708ce2d86b658294707572b3c` |
| `file(1)` | PE32+ executable for MS Windows 6.00 (console), x86-64, 9 sections |
| License | curl License (ISC-style); redistributable. Binary not committed. |

The zip SHA-256 matches the publisher `.txt`. `curl.exe` was not executed.

## Protocol

```text
uv run r2b brief BIN --quick --no-save --json
# only if subject.dangerous_imports includes system/popen/exec*:
uv run r2b verify BIN --import <name> --json
```

No model call. No decompile. `--quick` only.

## Result

`--quick` identified a Windows PE, x86_64/64, 276 functions, 276 imports.
`dangerous_imports` is `memcpy`, `memmove`, `strcat`, `strcpy`. That is
not `system` / `popen` / `exec*`, so `verify` was not run.

Ranked regions:

| Rank | id | score | kind |
|---|---|---|---|
| 1 | `imports:network` | 90 | inventory (`accept`/`bind`/`connect`/`listen`/`recv*`/`send*`/`socket`) |
| 2 | `entry:entry` | 89 | disasm @ `0x1400013a0` |
| 3 | `imports:memory` | 84 | inventory (`memcpy`/`memmove`/`strcat`/`strcpy`) |

`handoff.next_argv` is `[]`. It does not contain `decompile`.

Network ranking is expected for curl. Import names are pivots, not
callers and not a vulnerability.

## Timing

Recorded on Kali Pi 5 (ARM64, 4 CPUs, 8 GiB) with r2b 0.1.0, radare2
6.0.5, file 5.47, Python 3.11.13. Tree: `2bfe565`. `--quick` only;
Ghidra 12.1.2 is installed and was not used.

| Mode | Wall |
|---|---|
| `brief --quick` | 40.91 s |
| `verify` | not run |

GNU time is absent on this host; wall time is `perf_counter` around the
CLI.

## Reproduce

```bash
curl -L -o curl-8.22.0_1-win64-mingw.zip \
  https://curl.se/windows/dl-8.22.0_1/curl-8.22.0_1-win64-mingw.zip
# SHA-256 7f23b039f6ea4197362d4468e1a0e71428201222e1bef3b680d5ef7b2aefb714

python3 -c "import zipfile; z=zipfile.ZipFile('curl-8.22.0_1-win64-mingw.zip'); \
  z.extract('curl-8.22.0_1-win64-mingw/bin/curl.exe', '.')"

file curl-8.22.0_1-win64-mingw/bin/curl.exe
uv run r2b brief curl-8.22.0_1-win64-mingw/bin/curl.exe --quick --no-save --json
```

Do not execute `curl.exe`. Do not commit the zip or the PE.

## Limits

- r2b did not claim a bug in curl.
- `verify` correctly stayed off: no process-launch import.
- `memcpy`/`strcpy` inventory is not a memory-corruption finding.
- GitHub does not attach this Windows zip; curl.se does.
