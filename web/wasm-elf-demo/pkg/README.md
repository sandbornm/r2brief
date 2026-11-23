# r2brief-core

Client-side ELF triage core for [r2brief](https://github.com/sandbornm/r2brief).
Pure Rust, compiles to native and to WebAssembly. The same bytes in → the same
report out. No network, no upload, no clock.

## What it does (and what it does not)

**Does, with evidence cited to exact file offsets / VAs:**

- Header, program-header and section-header bounds checks (all offset math is
  checked; hostile inputs produce findings, not panics)
- Entry point outside an executable `PT_LOAD`, or inside a non-exec section
- RWX and overlapping `PT_LOAD` ranges; `PT_LOAD` file range past EOF
- `PT_NOTE`→`PT_LOAD` (structural): an executable `PT_LOAD` that sits outside
  the contiguous run of `PT_LOAD`s in the phdr table. Works on sectionless
  (sstrip'd) files. Does not fire on legacy single-RX non-PIE layouts.
- Text-padding infection: executable `PT_LOAD` in the page slack after the
  text segment
- `DT_INIT` / `DT_FINI` / `.init_array` / `.fini_array` / `.preinit_array`
  pointers outside `PF_X`. Slots are read through `R_*_RELATIVE` addends
  (x86-64 type 8, AArch64 type 1027), which is what `ld.so` actually uses in
  a PIE, so a hijack that only patches the relocation is caught. Oversized
  `DT_*ARRAYSZ` is flagged.
- Unusual / malformed `PT_INTERP`; missing section headers; stripped symtab
- Dangerous-import listing (the same set as r2b's `_DANGEROUS_IMPORTS`)
- Function-start recovery for x86-64 and AArch64: `.eh_frame` FDEs (with
  `.eh_frame_hdr` fallback), `e_entry`, `DT_INIT`/`DT_FINI`, init_array slots,
  direct call targets, address-taken code pointers (RIP-relative `lea`,
  `adrp`+`add`, RELATIVE addends), and a prologue scan when `.eh_frame` is
  sparse. Starts must land in an `SHF_EXECINSTR` section when section headers
  exist. PLT stubs are split out (by section name, or by stub shape when there
  are no sections).
- Deterministic `.r2br` evidence bundle (`r2b.bundle.v1`) readable by
  `r2b bundle inspect`

**Does not claim (cut because no fixture verifies it):**

- Reverse-text infection (detector exists, not shown, no fixture)
- PLT/GOT hijack and `DT_NEEDED` injection detection
- Overlapping-LOAD demo (rule exists, no fixture)
- Sink call-site listing (would need objdump-verified xrefs; not implemented)
- `DT_RELR` relocations (not parsed; RELR-packed init arrays fall back to the
  section bytes)
- Embedded / Cortex-M recovery (separate workstream); any dynamic analysis

## Measured accuracy

`eval/score.py` regenerates `eval/RESULTS.md` (per binary: truth, predicted,
TP, precision, recall, missed names, extra addresses). Current numbers on the
fixture corpus, ±4 bytes, ground truth = `STT_FUNC` in executable non-PLT
sections of the unstripped twin:

| variant | x86-64 P / R | AArch64 P / R |
|---|---|---|
| stripped PIE | 1.000 / 0.974 | 1.000 / 1.000 |
| stripped, no unwind tables | 0.974 / 0.974 | 0.975 / 1.000 |
| non-PIE, noseparate-code | 1.000 / 0.974 | 0.976 / 1.000 |
| sstrip (no section headers) | 1.000 / 0.974 | 1.000 / 1.000 |

The one x86-64 miss everywhere is `register_tm_clones` (no FDE, reached only
by a tail jump). Infection rules: 12/12 expected rule ids hit, 0 infection-class
findings on 10 clean binaries. This is one ~40-function program; treat the
numbers as a regression floor (CI fails below 0.9), not a general claim.

## Build

```bash
cargo build --release
cargo test --release
wasm-pack build --target web --out-dir ../../web/wasm-elf-demo/pkg \
  --release -- --features wasm --no-default-features
```

## Fixtures

```bash
# Linux container with gcc + x86_64/aarch64 cross toolchains
docker run --rm -v "$PWD/fixtures:/work" -w /work r2b-elf-fixtures:24.04 \
  python3 build_fixtures.py
./target/release/r2brief-core fixtures/bin/triage-x86_64-note --json
python3 eval/score.py
```

## CLI

```bash
r2brief-core path/to/elf [--json] [--bundle out.r2br]
```

## Browser demo

Serve `web/wasm-elf-demo/` (any static file server). Open the page, click a
fixture or drop a local ELF. Analysis runs in a Web Worker; the file never
leaves the tab. Not deployed to r2brief.com until explicitly approved.
