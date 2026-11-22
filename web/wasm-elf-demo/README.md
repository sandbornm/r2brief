# r2brief-core browser demo

Static page that loads `r2brief-core` as WebAssembly inside a Web Worker,
analyzes a local ELF, and shows findings with byte offsets. Nothing is
uploaded. Fixture ELFs under `samples/` are original synthetic binaries
(see `crates/r2brief-core/fixtures/`).

```bash
# from repo root, after wasm-pack build
python3 -m http.server 8765 --directory web/wasm-elf-demo
# open http://127.0.0.1:8765/
```

Not wired into the main r2brief frontend deploy. Do not publish to
r2brief.com until explicitly approved.
