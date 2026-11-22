# Stripped Rust eval (CI subset)

CI job `Stripped Rust eval (fd aarch64)` measures how well `r2b brief --quick`
puts a stripped Rust binary's own code at the top of its ranked regions.

- Subject: fd-find 10.5.2 (MIT OR Apache-2.0) from crates.io, checked against
  its pinned SHA-256 and built `--locked` with rustc 1.93.0 for
  `aarch64-unknown-linux-gnu` using the Ubuntu cross gcc. No binary is
  committed.
- Variants ranked: `strip` (`aarch64-linux-gnu-strip --strip-all` on a
  symbolized build) and `cargostrip` (Cargo `strip = "symbols"`).
- Ground truth: every `.text` function symbol from a symbolized twin whose
  `.text` and `.rodata` are byte-identical to the stripped binary
  (`truth.py` refuses to write truth otherwise). The `cargostrip` twin is
  built with the same profile plus `-C strip=none` on the final link,
  because the Cargo setting changes every crate's metadata hash and with it
  the code layout. A function is user code when its demangled path
  (independent `rust-demangler`, MIT) belongs to crate `fd`.
- Score: `scripts/eval_ground_truth.py` p@5 and p@10 over the ranked
  addresses, each true function counted once.
- Soft floor: `baseline.json`. The job fails only when a score drops more
  than one hit below baseline (0.2 at k=5, 0.1 at k=10) or r2b emits no
  briefing. Raise the baseline in the PR that improves ranking.

Reproduce locally (Linux, rustup, `gcc-aarch64-linux-gnu`, `libc6-dev-arm64-cross`, `make`):

```sh
rustup toolchain install 1.93.0 --profile minimal --target aarch64-unknown-linux-gnu
uv sync --locked --extra r2
uv pip install --require-hashes -r scripts/rust_eval/requirements.txt
RUSTUP_TOOLCHAIN=1.93.0 scripts/rust_eval/run.sh /tmp/rust-eval
```
