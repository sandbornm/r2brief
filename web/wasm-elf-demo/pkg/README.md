# r2brief-core

Client-side ELF triage core for [r2brief](https://github.com/sandbornm/r2brief).
Pure Rust, compiles to native and to WebAssembly. The same bytes in → the same
report out. No network, no upload, no clock.

## What it does (and what it does not)

**Does, with evidence cited to exact file offsets:**

- Header / program-header / section consistency checks
- Entry point outside executable `PT_LOAD`
- RWX and overlapping `PT_LOAD` ranges
- Suspected `PT_NOTE`→`PT_LOAD` infection (isolated small executable LOAD)
- Text-padding infection (executable LOAD in `.text` page slack)
- `.init_array` / `DT_INIT` / `DT_FINI` hijacks (pointer outside PF_X)
- Interpreter tampering / unusual `PT_INTERP`
- Stripped-symbol status and dangerous-import listing (r2b's set)
- Function-boundary recovery for x86-64 and AArch64 (`.eh_frame` FDE starts,
  direct call targets, prologue scan when `.eh_frame` is sparse)
- Deterministic `.r2br` evidence bundle (`r2b.bundle.v1`) readable by
  `r2b bundle inspect`

**Does not claim (cut as unverifiable on our fixtures):**

- Reverse-text infection as a demo feature (detector exists; no fixture yet)
- Full PLT/GOT graph reasoning beyond DT_NEEDED / import names
- Embedded / Cortex-M recovery (that lives in the separate firmware workstream)
- Any dynamic / behavioral analysis

Precision and recall for function recovery are measured against symbol-keeping
twins of our own synthetic binaries. Infection rules are checked against
hand-crafted rewrites of those same binaries. See `eval/results.json`.

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
