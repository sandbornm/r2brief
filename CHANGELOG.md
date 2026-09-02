# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version source of truth: `pyproject.toml`. GitHub Releases are tags `vX.Y.Z`.

## Unreleased

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
- `handoff.next_argv` follows subject class: ELF `verify`/`decompile ADDR`,
  firmware child `brief` or `--extract`. Missing file is exit 1.
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
