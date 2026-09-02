# AArch64 investigations

These are read-only investigations of public, redistributable binaries. Each
one answers a narrow question or records a useful limit. They are not fixtures
written to flatter the ranker. Target code is downloaded, hash-checked, and
analyzed; it is never executed. Third-party binaries are not committed.

| Investigation | Question answered |
|---|---|
| [OpenWrt uHTTPD: following a request to `execl`](uhttpd-aarch64.md) | What path, dispatch, process, and configuration boundaries sit between an HTTP request and CGI launch? |
| [Review width on three AArch64 programs](review-width-aarch64.md) | When do independent lenses expose a new evidence capsule, and when does another pass add nothing? |
| [AArch64 first-pass corpus](corpus-aarch64.md) | Which real programs produce a concrete follow-up, and which correctly stop with a thin brief? |
| [DARPA CGC Palindrome and basic_messaging](darpa-cgc-pilot.md) | Does following ranked `main` plus two callee hops reach a planted CGC change without reading the README, or only on a cherry-picked sample? |
| [NIST Juliet C/C++ 1.3 retrieval slice](nist-juliet-pilot.md) | On matched good/bad aarch64 ELFs, does `--quick` ranking point at the labelled sink function, or only at `entry:main` / an import name? |
| [curl.exe Windows amd64](pe-curl-win64.md) | Does a public PE `--quick` stay thin when there is no process-launch import? |
| [jq macOS arm64](macho-jq.md) | Does a public Mach-O `--quick` on Linux stay thin, with empty `next_argv`? |

GNU Hello is kept separately as a [calibration sample](../calibration/hello-aarch64.md),
not presented as an investigation. It catches noisy risk language on a known
benign target.

[`scripts/fetch_case_studies.sh`](../../scripts/fetch_case_studies.sh)
recreates the public inputs in a temporary directory. It validates package and
extracted-binary SHA-256 values, and it never invokes a target.

## Reproduce the investigation

```sh
./scripts/fetch_case_studies.sh /tmp/r2b-case-studies

R2B_INPUT=/tmp/r2b-case-studies/uhttpd/usr/sbin/uhttpd
r2b brief "$R2B_INPUT" --quick --no-save --json
r2b verify "$R2B_INPUT" --import execl --json
```

Expected extracted target:

```text
2dea2e1017dd4839b375fff5a531b0d8c3317d8d031a3d44f0c2849cda1b0941  uhttpd
```

Raw outputs are under [`results/`](results/). Absolute `/tmp` or
`/private/tmp` paths are expected because the files are unedited command
output. Timings are setup references, not benchmarks.

Recorded 2026-08-30 on Darwin arm64 with Python 3.11.9, r2b 0.1.0 from the
working tree based on `ea5edce8a444498bad5476bebe027ebf47eb79bb`, radare2
6.0.7, and file 5.41. Optional deep analyzers were not enabled. A Kali
aarch64 replay of the same package `verify` sites is in
[`corpus-aarch64.md`](corpus-aarch64.md).
