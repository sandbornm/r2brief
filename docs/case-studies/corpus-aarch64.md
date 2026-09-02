# AArch64 first-pass corpus

This set checks whether a quick brief leaves a useful next step on real
programs. It is not a vulnerability benchmark. A useful result can be a caller
to inspect, a smaller group of addresses, or an honest stop when the quick
evidence is thin.

All five programs come from the same OpenWrt 24.10.4
`aarch64_cortex-a53` package feed. They are stripped, sectionless ELF files.
[`scripts/fetch_case_studies.sh`](../../scripts/fetch_case_studies.sh) pins the
package and extracted-binary SHA-256 values. It downloads and extracts the
packages without running the targets.

## Current set

| Program | Job | Quick result | Narrow follow-up |
|---|---|---|---|
| uHTTPD | HTTP server and CGI dispatcher | Process launch ranks first in a binary with 116 functions and 117 imports. | `verify execl` recovers one GOT-indirect call at `0x9384`; the [worked investigation](uhttpd-aarch64.md) follows it to the CGI boundary. |
| dnsmasq | DNS and DHCP service | Process launch and network edges rank ahead of entry. | `verify popen` recovers two dynamic call sites. Their command strings still need decompilation or source review. |
| rpcd | JSON-RPC backend | Process launch ranks first in a binary with 145 functions and 147 imports. | `verify execl` and `verify execv` recover six dynamic call sites across the two imports. This is a useful multi-caller scope, not a behavior verdict. |
| BusyBox | Multi-call utility | Six broad import capsules describe a program that implements many unrelated commands. | `verify execl` recovers one dynamic caller. The result also shows where category ranking becomes too coarse for a large multi-call binary. |
| ubus | Small RPC client | Entry and memory/path are the only regions; no process or network capsule is present. | The brief offers one-function decompilation at entry. This is the real-program thin control. |

GNU Hello remains a separate benign calibration target. The small C programs
under `samples/` remain regression fixtures. Neither group is product proof.

## What this set covers

- one recovered indirect AArch64 call;
- multiple callers behind two process imports;
- a noisy multi-call program;
- a real program where the quick pass has little to say; and
- identical package provenance and architecture across the set.

The set does not cover every public format claim. PE and Mach-O currently have
format and shallow-analysis tests, but no comparable public investigation.
The firmware path also needs a pinned image that contains several children and
produces a useful extraction handoff. A version pair of the same OpenWrt daemon
would be the next corpus addition because it would exercise tagged records and
field comparison without claiming semantic function similarity.

## Commands used for the narrow checks

```sh
r2b verify "$CORPUS/uhttpd/usr/sbin/uhttpd" --import execl --json
r2b verify "$CORPUS/dnsmasq/usr/sbin/dnsmasq" --import popen --json
r2b verify "$CORPUS/rpcd/sbin/rpcd" --import execl --json
r2b verify "$CORPUS/rpcd/sbin/rpcd" --import execv --json
r2b verify "$CORPUS/busybox/bin/busybox" --import execl --json
r2b brief "$CORPUS/ubus/bin/ubus" --quick --no-save --json
```

The verifier reports static call sites and first-argument recovery. A dynamic
argument means the caller address is useful but the value is still unresolved.

## Kali Pi replay (2026-09-02)

Re-run on Kali GNU/Linux Rolling 2026.3, Raspberry Pi 5
(`Linux kali-raspberry-pi5 6.1.92-v8+ aarch64`, 4 CPUs, 8 GiB), r2b 0.1.0,
radare2 `6.0.5 0 @ linux-arm-64`, Python 3.11.13. Packages were fetched with
[`scripts/fetch_case_studies.sh`](../../scripts/fetch_case_studies.sh)
`/tmp/r2b-case-studies`. Package and extracted-binary SHA-256 values matched
the script pins. BusyBox is the OpenWrt *package* binary, not a firmware
image. Targets were not executed.

| Tool | Version |
|---|---|
| r2b | 0.1.0 |
| radare2 | `radare2 6.0.5 0 @ linux-arm-64` |
| file | `file-5.47` |
| Python | 3.11.13 |

### `brief` / `next_argv`

`uv run r2b brief BIN --quick --no-save --json` ranked the same capsules as
the Darwin first pass. Function and import counts matched the table above.
`handoff.next_argv` queued `r2b verify --import …` for process-launch
imports. It did not queue `decompile`.

| Program | Ranked regions | `next_argv` | Wall |
|---|---|---|---:|
| uhttpd | process, network, entry, runtime, memory | `verify --import execl` | 25.1 s |
| dnsmasq | process, network, entry, memory, control | `verify --import execl`, `verify --import popen` | 23.8 s |
| rpcd | process, entry, runtime, memory | `verify --import execl`, `verify --import execv` | 30.9 s |
| busybox | process, network, entry, runtime, memory, control | `verify` for `execl`, `execv`, `execve`, `execvp` | 28.2 s |
| ubus | entry, memory | empty | 25.6 s |

ubus is still the thin control: no process or network capsule. The Darwin
writeup offered one-function decompilation at entry. Current `next_argv`
stays empty instead of auto-queuing `decompile`.

### `verify` sites versus Darwin

The Darwin writeup published a call address only for uhttpd (`0x9384`). The
other programs were specified by site count. Kali recovered the same counts,
and the uhttpd GOT-indirect site is the same address.

| Program | Import | Kali sites | Darwin expectation | Match |
|---|---|---|---|---|
| uhttpd | execl | `fcn.000092e4` @ `0x00009384` dynamic | one GOT-indirect at `0x9384` | yes |
| dnsmasq | popen | `0x0001352c`, `0x00023efc` dynamic | two dynamic sites | yes (count) |
| rpcd | execl | three dynamic (`0x0000acdc`, `0x0000b224`, `0x0000bde8`) | six across `execl`+`execv` | yes |
| rpcd | execv | two dynamic (`0x000040ac`, `0x00004c1c`) | (included above) | yes |
| busybox | execl | `fcn.0040be40` @ `0x0040bf7c` dynamic | one dynamic caller | yes (count) |
| ubus | — | not run | none expected | n/a |

Raw JSON is under [`results/`](results/) as `kali-*-quick.json` and
`kali-*-verify-*.json`. The compact index is
[`results/kali-corpus-aarch64.json`](results/kali-corpus-aarch64.json).

### Abstentions

- Targets were not executed.
- No model call.
- No decompile.
- `verify` was not run on ubus.
- Extra `next_argv` imports (`dnsmasq` `execl`; busybox `execv` / `execve` /
  `execvp`) were not verified. The Darwin first-pass checks used `popen` and
  `execl` respectively.
