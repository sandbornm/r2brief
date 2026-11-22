# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version source of truth: `pyproject.toml`. GitHub Releases are tags `vX.Y.Z`.

## Unreleased

- Stripped Rust ARM ranking is back to user code first. On fd-find 10.5.2
  for aarch64 (`strip` and `cargostrip`), user-code p@5/p@10 goes from
  0.2/0.2 to 1.0/0.8. The causes: std's vendored `/rust/deps/` crates
  counted as user crates. Callee-saved spills after `stp x29, x30` ended
  the prologue, so the following `sub sp, sp` was taken as a second
  function start. The epilogue `sub sp, x29, #imm` was taken as a start
  too. The user-main scan stopped before the `lang_start` pointer load in
  an LTO-inlined C `main`. A path-referencing function that user main
  also calls now gets a one-time +4. Thumb `sub sp, #imm` still starts a
  function. Static analysis only, no model.
- Rust triage no longer reads the ELF and program headers as program
  data. A load through a stale small register could read `e_shoff` from
  the mapped ELF header. When that value matched a panic Location, it
  counted as a false registry ref and dropped `fd::run` out of the top
  10. That happened on the CI build of fd (p@10 0.7) but not on local
  builds, whose file size differs.
- v0 demangling rejects malformed punycode instead of publishing a
  `-tail` spelling, so `pretty_symbol` keeps the raw name.
- A short ELF read (file ends before a section's declared size) raises
  `ElfShortRead` instead of returning a short slice. Rust triage drops
  that section and keeps going.
- Extractor sandbox: added a test pinning that a tool symlink to `$HOME`,
  `/`, `/tmp`, or `/var/tmp` binds neither the link nor its target. This
  already held on `main`, so there is no behavior change.
- CI job `Stripped Rust eval (fd aarch64)` builds fd-find 10.5.2 for
  aarch64 (pinned crate, rustc 1.93.0, no committed binaries), derives
  per-function truth from a byte-identical symbolized twin, and reports
  user-code p@5/p@10 for `r2b brief --quick` on the `strip` and
  `cargostrip` variants in the job summary. It fails only on a drop of
  more than one hit below `scripts/rust_eval/baseline.json`, which is set
  to 1.0/0.8 for both variants.
- `r2b brief` on a stripped Rust ARM ELF adds a `rust` object
  (`rustc_version`, `rustc_commit`, `user_crates`, `user_main`,
  `entry_chain`, `functions`) and ranks user functions, with real
  addresses, above entry and imports. Recovery is static. It follows
  the `lang_start` pointer, reads panic `Location` paths, and an in-tree
  demangler. Non-Rust binaries are unchanged. `handoff.decompile_addrs`
  is still not a decompile queue. Review follow-ups: consecutive PAC
  prologues are one function start, AArch64 ADR uses the absolute
  Capstone operand, callee discovery stops at `ret`, Thumb-2 Linux is
  decoded as Thumb, and a bad mangled name can no longer abort
  `build_briefing`. The extractor sandbox binds the tool itself, not a
  home directory.
  Later review follow-ups: AArch64 `stp`/`ldp` uses a 4-byte stride for `w`
  registers and honors post-index writeback; the extractor sandbox never
  binds a symlink whose resolved target is denylisted; a spent ELF read
  budget raises instead of returning a short or empty read, and optional
  Rust triage records a skip note rather than aborting the briefing; v0
  punycode keeps underscores in the ASCII prefix (`α_ω`).
- Briefing `next_steps` / import `next_actions` emit `r2b verify` /
  `r2b decompile`, not `r2 axt`. `handoff.named_imports` lists buffer
  imports that verify can take without auto-queueing them on `next_argv`.
  `brief --verify` follows `subject.dangerous_imports`. Verify JSON is
  `r2b.verify.v1`; the human table prints `function_addr` and a decompile
  argv line.
- `r2b verify` JSON includes `call_sites[].function_addr` (containing-function
  VA). `r2b decompile BIN ADDR` resolves a call site to that function instead
  of emitting empty C / `no function at <call site>`.
- `handoff.next_argv` no longer auto-queues `r2b decompile`. It emits
  `verify` for process-launch imports, extract/brief for wrappers, and
  `records show` when a record exists. Empty is valid. Function VAs stay
  on `handoff.regions[].addr`.
- `r2b decompile` expands `~` in `ghidra.project_dir` and defaults to
  `~/r2b/ghidra-projects`. analyzeHeadless rejects XDG paths whose
  elements start with `.` (including `~/.local/share`), which made the
  advertised `handoff.next_argv` decompile command return empty C.
- CLI binaries are `r2b` and `r2b-web`. Library import, schema ids, and
  `R2B_*` env vars use the same surface.
- AArch64 verification recognizes direct `bl` and indirect `blr` calls and
  preserves the real caller name from radare2 xrefs.
- Ghidra Java scripts ship inside the wheel and are passed through
  `-scriptPath`; one-function and deep analysis no longer copy scripts into
  `~/ghidra_scripts`.
- `brief --json` includes deterministic `handoff` (`next_argv` + compact
  regions). `--ask` attaches `ask_result` on the same stdout JSON.
- `review` emits `r2b.review.v1`: `rules` makes no model call, while `llm`
  and `both` may only reorder known region and evidence IDs. The briefing,
  scores, and handoff remain unchanged; review tool calls are disabled in v1.
- Review artifacts include a deterministic evidence-maturity screen. Raw
  pivots remain visible but can be marked low-signal; complete negative import
  verification can lower priority, while partial coverage cannot.
- `handoff.next_argv` follows subject class: ELF `verify` for
  process-launch imports, firmware child `brief` or `--extract`.
  Missing file is exit 1.
- CI smokes `r2b brief /bin/ls --quick --json`. Dependabot is monthly
  grouped. `analyze --json` emits the briefing. `pilot` is hidden.
- Artifact DAG, sandboxed extract, citation grounding, setup flavors.
- GitHub Release packaging (wheel, sdist, frontend, contracts, checksums).
- Default Python deps are CLI-only. Flask is extra `web`, openai/anthropic
  extra `llm`, ghidra-bridge extra `ghidra` (PyPI, not git). Checkout
  `uv sync` still runs the product (dev group = r2+web+llm). Extra `std`
  is the same set for wheels. Flavor tomls ship in the wheel.
- NOTICE credits radare2, Ghidra, Capstone, angr, extractors, and SDKs.

## 0.1.0

- Initial tagged layout: `brief` / `verify` / `decompile` / `records` / `insights`.
