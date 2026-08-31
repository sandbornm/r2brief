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
