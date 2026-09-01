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
failed on the macOS host, but regular files were recovered and indexed.

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
