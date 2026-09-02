# OpenWrt release delta: from two firmware images to one `ubusd` routine

This run compares the official OpenWrt 24.10.3 and 24.10.4 firmware images for
the same Banana Pi BPI-R3 Mini target. It is a release-delta exercise, not a
claim that r2b discovered a new vulnerability.

The useful result is the reduction:

```text
2 signed release images
└── 176 regular ELFs in each root filesystem
    └── 109 paths present in both releases
        ├── 106 unchanged
        └── 3 changed: busybox, ubusd, odhcpd
            └── ubusd
                └── 3 dynamic strcpy caller leads
                    └── event-registration routine
                        └── missing empty-pattern guard in 24.10.3
```

The complete, machine-readable result is
[`openwrt-ubusd-release-delta.json`](openwrt-ubusd-release-delta.json).

## Inputs

| Release | Firmware SHA-256 | Official files |
|---|---|---|
| 24.10.3 | `6f7dea199d326ca6efcc3c2a11932070edf79fa6d0984e2a4d77cef8c4cbb8a4` | [mediatek/filogic](https://downloads.openwrt.org/releases/24.10.3/targets/mediatek/filogic/) |
| 24.10.4 | `8d632977278bfe58b53e20218dc72571b20b8da589ad28184642a5c3be37263b` | [mediatek/filogic](https://downloads.openwrt.org/releases/24.10.4/targets/mediatek/filogic/) |

Both images were hash-checked before analysis. Binwalk found the SquashFS at
`0x56c000`; `unsquashfs` recovered the root filesystems. Device-node creation
failed on the original macOS host and again on the Kali replay without
superuser; regular files were recovered and indexed on both.

## The first useful cut

Each root filesystem contained 176 regular ELF files. Comparing paths and
SHA-256 values produced 109 directly comparable paths:

- 106 were unchanged.
- `bin/busybox`, `sbin/ubusd`, and `usr/sbin/odhcpd` changed.
- 67 paths appeared only on each side. Most were kernel modules under the
  release-specific `6.6.104` and `6.6.110` directories or versioned library
  filenames, so they were kept separate from the common-path comparison.

This is the main value of the pass. `uhttpd`, for example, has the same SHA-256
in both releases. There is no reason to reopen its CGI path for this
release question.

## From `ubusd` to a routine

The 24.10.3 `ubusd` SHA-256 is
`8fd16a06d3b529ee4899bf73c6ac283e8b030972205a8356da4fc2fc98dae5f3`.
The 24.10.4 SHA-256 is
`d279564b22768de6e9d8efe083784c4547c3aeadf6ffd1905356a0e0df1f2765`.

The brief ranked the network boundary, entry point, and memory/path imports.
That is only orientation. An imported `strcpy` does not prove an overflow.
`r2b verify` reduced it to three dynamic call sites in 24.10.3:

```text
0x00004b50
0x00004b6c
0x00004ba8
```

Targeted Ghidra decompilation of the containing routine at `0x00104a3c`
showed the event `register` path. The relevant order in 24.10.3 is:

```c
len = strlen(pattern);
last = pattern[len - 1];
/* wildcard and ACL handling */
strcpy(destination, pattern);
```

The corresponding 24.10.4 routine at `0x001049a0` contains a guard before the
last-byte access:

```c
len = strlen(pattern);
if (0 < len) {
    last = pattern[len - 1];
    /* wildcard, ACL, allocation, and copy */
}
```

The [upstream fix](https://github.com/openwrt/ubus/commit/d31effb4277bd557f5ccf16d909422718c1e49d0)
names the routine `ubusd_alloc_event_pattern` and states the source-level
change directly: reject empty patterns before reading `pattern[len - 1]`.
OpenWrt's [advisory](https://github.com/openwrt/openwrt/security/advisories/GHSA-cp32-65v4-cp73)
provides the security classification and affected-release ground truth.

## What full analysis contributed

The selected 24.10.3 binary was run through the enabled static toolchain:

| Adapter | Result |
|---|---|
| radare2 | completed; 63 functions and 71 imports |
| Ghidra | completed; 130 functions |
| angr | completed; 300 stored CFG nodes and 381 stored edges |
| Capstone | partial; instruction listing only |
| DWARF | completed; no debug information present |

No model was called and the AArch64 target was not executed. Frida and GEF
were left off because foreign-architecture runtime work is an explicit step,
not part of a static `full` pass.

Review width did not manufacture another result. Width 1 selected network and
entry regions, width 2 added nothing, and width 3 added the saved memory/path
region. That is a useful stop signal: after the caller list exists, targeted
decompilation adds more than another ranking pass.

## What r2b did and did not do

r2b did not discover or prove CVE-2025-62526 on its own. Exact hashing found
the release delta. r2b preserved the extracted-child relationship, tool
coverage, ranked binary evidence, caller leads, one-function decompilation,
review overlay, and next commands. The upstream patch and advisory supplied
the names and ground truth.

That division is intentional. The point is to get from a firmware pair to the
few addresses worth opening without losing how the path was chosen.

## Kali Pi replay (2026-09-02)

Re-run on Kali GNU/Linux Rolling 2026.3, Raspberry Pi 5
(`Linux kali-raspberry-pi5 6.1.92-v8+ aarch64`, 4 CPUs, 8 GiB), r2b 0.1.0,
Python 3.11.13. Images were fetched with `scripts/corpus_intake.py` and
hash-checked before extract. `allow_unsafe_fallback` stayed false.

| Tool | `r2b env` |
|---|---|
| radare2 | `radare2 6.0.5 0 @ linux-arm-64` |
| binwalk3 | `binwalk 3.1.0` |
| unblob | `26.6.4` |
| bubblewrap | `bubblewrap 0.11.2` |
| unsquashfs | `unsquashfs version 4.7.5 (2026/03/01)` |
| sasquatch | `unsquashfs version 4.5.1 (2022/03/17)` |
| file | `file-5.47` |

Extract isolation used bubblewrap `--unshare-net`. Without `bwrap`,
`run_sandboxed` returns 126 and does not run the extractor.

### Inventory

Both images still have SquashFS at `0x56c000`. The ITB wrapper was not treated
as code: `r2b brief --extract --quick` skipped radare2 on the container and
ranked the SquashFS child. Default extract caps (`max_files=200`) do not keep
every rootfs ELF. The table below is from `unsquashfs` under the same sandbox
with a higher file cap. `unsquashfs` exit 2 is the device-node miss
(`/dev/console` needs superuser). That is not macOS-specific.

| Release | Regular files | Regular ELFs |
|---|---|---|
| 24.10.3 | 1201 | 176 |
| 24.10.4 | 1201 | 176 |

Path and SHA-256 comparison matched the original cut: 109 common paths, 106
unchanged, 3 changed. 67 paths exist only on each side (64 kernel modules
under `6.6.104` vs `6.6.110`, plus mbedTLS `3.6.4` vs `3.6.5`).

| Path | 24.10.3 SHA-256 | 24.10.4 SHA-256 |
|---|---|---|
| `bin/busybox` | `9f8f1d0c…85836b4` | `2032e4d0…953fa6c` |
| `sbin/ubusd` | `8fd16a06…98dae5f3` | `d279564b…df1f2765` |
| `usr/sbin/odhcpd` | `9c5ec590…e3b2e13a` | `b0f7fc5f…83271a25` |
| `usr/sbin/uhttpd` (control) | `4c2dd929…d480e2` (unchanged) | same |

`ubusd` hashes match the original case.

### `brief` / `verify`

`r2b brief --quick` on both `ubusd` binaries ranked `imports:network`,
`entry:entry`, then `imports:memory` (`memcpy`, `sprintf`, `strcpy`). Quick
scan function counts were 70 (24.10.3) and 77 (24.10.4); those are not the
original deep radare2 counts (63 / 64).

`r2b verify --import strcpy` on 24.10.3 still reports three dynamic callers:

```text
0x00004b50  000033c4
0x00004b6c  unknown
0x00004ba8  00004a3c
```

Those are the same addresses as the original writeup. The third site is still
the event-registration routine at `0x00104a3c`. 24.10.4 still has three
`strcpy` sites; the third is in `000049a0` (`0x001049a0`). `memcpy` is also
dynamic (6 sites in 24.10.3, 5 in 24.10.4) and was not used as the lead.

No decompile was queued. The firmware was not executed.

### The other two changed ELFs

`r2b brief --quick --no-save` and targeted `verify` on `bin/busybox` and
`usr/sbin/odhcpd`, both releases. No decompile. No CVE claim. The firmware
was not executed.

| Path | Release | Regions | Verify | Lead |
|---|---|---|---|---|
| `bin/busybox` | 24.10.3 `9f8f1d0c…85836b4` | `imports:process`, `imports:network`, `entry:entry`, `imports:runtime`, `imports:memory`, `imports:control` | process-launch + `strcpy`/`memcpy`; maps identical to 24.10.4 | rebuild noise |
| `bin/busybox` | 24.10.4 `2032e4d0…953fa6c` | same | same addresses and statuses | rebuild noise |
| `usr/sbin/odhcpd` | 24.10.3 `9c5ec590…e3b2e13a` | `imports:process`, `imports:network`, `entry:entry`, `imports:memory`, `imports:control` | `execv` dynamic 1; `strcpy` dynamic 3; `memcpy` dynamic 18 | import map changed |
| `usr/sbin/odhcpd` | 24.10.4 `b0f7fc5f…83271a25` | same region ids | `execv` dynamic 1; `strcpy` dynamic 1; `memcpy` dynamic 19 | not followed to a patched routine |

`busybox` is 458773 bytes on both sides, 301 functions, 299 imports. Ranked
regions and verify maps match. `execl` 1 dynamic, `execlp` 3, `execv` 2,
`execve` 1, `execvp` mixed (3 sites, one constant `stty` at `0x00434ce8`),
`popen` 2, `system` 2, `strcpy` 81, `memcpy` 58. Eight bytes differ, all in
the banner at `0x5bcf0`: `BusyBox v1.36.1 (2025-09-19 21:19:38 UTC)` versus
`(2025-10-19 16:37:45 UTC)`. That is rebuild noise. The process-launch region
is real busybox surface, not a 24.10.3/24.10.4 patch lead.

`odhcpd` is not that. Size 132025 → 132113, functions 157 → 179, imports
159 → 182. Memory capsule drops `memmove` and picks up `realpath`. `strcpy`
callers in `00005b1c` go from three (`0x00005bf8`, `0x00006b14`, `0x00006c1c`)
to one (`0x0000734c` in `0000726c`). `execv` stays one dynamic site
(`0x0000db7c` / `0x0000d9f0`). That is a useful caller-list delta, not a
rebuild stamp. It was **not followed to a patched routine**: no decompile,
no named function, no advisory.

### Tagged insights (`ubusd`)

Saved records (no `--no-save`) with `--tag ubusd`, then
`r2b insights --tag ubusd --json`.

| Record | SHA-256 |
|---|---|
| 24.10.3 | `8fd16a06d3b529ee4899bf73c6ac283e8b030972205a8356da4fc2fc98dae5f3` |
| 24.10.4 | `d279564b22768de6e9d8efe083784c4547c3aeadf6ffd1905356a0e0df1f2765` |

`r2b.insights.v1` was ready on two `linux_elf` siblings. Exact-SHA collapse
did **not** fire (`identity` pattern absent); the hashes differ. Eight
recurring import patterns, all 2/2: `avl_find`, `avl_strcmp`, `blob_buf_init`,
`blob_nest_end`, `blob_parse_untrusted`, `blobmsg_add_field`,
`blobmsg_add_json_from_file`, `blobmsg_open_nested`. `strcpy` / `memcpy` are
not listed (ubiquitous libc is dropped). `skill_ready` is false.

## Portable result

The generated `.r2br` contains the pre-fix `ubusd` analysis, briefing,
provenance, review, and tool status. Target bytes are excluded. Its SHA-256 is:

```text
90544b29015b3fddfefadb00fb3b332dee59e8718681c1896d8c1c894201cbaf
```

The v1 bundle holds one subject. The adjacent case JSON links that subject to
the two firmware releases and records the comparison. A native paired-release
bundle remains future work; this page does not pretend the single-subject
schema already provides one.
