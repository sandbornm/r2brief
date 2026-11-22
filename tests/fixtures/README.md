tiny-rust-aarch64-musl is a no_std AArch64 ELF built with rustc
--target aarch64-unknown-linux-musl -C panic=abort -C link-self-contained=no.
It exists so triage tests can run against a real rustc image, not only
hand-assembled ELF bytes.

cortex_m/ holds Cortex-M firmware built from synthetic sources in this
repository. fw/ is a cortex-m-rt 0.7.5 + panic-halt 1.0.0 application
(both MIT OR Apache-2.0; the crate itself is MIT) built for thumbv6m,
thumbv7m and thumbv7em-eabihf at -O0, release and -Oz, with and without
`#[pre_init]`. fwasm/ has no dependencies and uses global_asm to pin
Reset/main edge shapes (thumbv7m, release). Rebuild with Docker from the
repository root:

    docker run --rm -v r2b-fw-cargo:/usr/local/cargo/registry \
      -v "$PWD/tests/fixtures/cortex_m":/fx -w /fx rust:1.93.0-slim ./build.sh

bin/<name> is stripped with `llvm-strip --strip-all --keep-section=.comment`
(like arm-none-eabi-strip, it keeps the rustc version note); bin/<name>.sym
keeps the symbol table and is the source of truth. manifest.json records
each image's user main, read from the symbol twin. The build is
byte-reproducible with the locked dependencies.
