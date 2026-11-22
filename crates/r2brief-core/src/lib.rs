//! r2brief-core: static ELF triage that runs natively or as WebAssembly.
//!
//! Everything here is a pure function of the input bytes. No I/O, no
//! network, no clock, so the same bytes produce the same report in the
//! browser, in the CLI, and in CI.
// Offsets come from untrusted input: every add/mul/shift must be checked or
// saturating, or carry a local, justified allow. Enforced in CI via clippy.
#![deny(clippy::arithmetic_side_effects)]

pub mod anomalies;
pub mod bundle;
pub mod dynamic;
pub mod ehframe;
pub mod elf;
pub mod funcs;
pub mod imports;
pub mod report;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use report::{analyze, Report};
