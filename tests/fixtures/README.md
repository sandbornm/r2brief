tiny-rust-aarch64-musl is a no_std AArch64 ELF built with rustc
--target aarch64-unknown-linux-musl -C panic=abort -C link-self-contained=no.
It exists so triage tests can run against a real rustc image, not only
hand-assembled ELF bytes.
