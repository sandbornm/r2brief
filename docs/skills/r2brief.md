# Skill: r2brief triage loop

Use this skill when analyzing ELF / firmware binaries with **r2b**.
Analysis never calls a model. Never execute targets. Prefer `--json` on stdout.

## Invariants

- Shell only through `r2b-exec` (allowlisted) or direct `r2b` with the same verbs.
- Do not invent symbols, CWE/EMB3D tags, or gadget claims.
- Tags (`--cwe`, `--emb3d-tid`, `--emb3d-mid`, `--tags-file`) are analyst-supplied.
- `--gadgets` is optional, static, bounded, and off by default.

## Loop

1. `r2b-exec env --json` — confirm tools.
2. `r2b-exec brief BIN --quick --json` — ranked regions + `handoff.next_argv`.
3. Follow `handoff.next_argv` exactly when non-empty (usually `verify` for `system`/`popen`/`exec*`).
4. For buffer sinks on `handoff.named_imports`, run  
   `r2b-exec verify BIN --import NAME --json` (not auto-queued).
5. Optional: attach case tags  
   `… --tags-file PATH/TAGS.md` or `--cwe CWE-78 --emb3d-tid TID-310`.
6. Optional after verify: `… --gadgets` for a bounded ROP/gadget listing.
7. One `r2b-exec decompile BIN FUNCTION_ADDR --json` using `function_addr` from verify.
8. Persist evidence: `r2b-exec bundle create BIN -o out.r2br --tags-file …`.

## Do / don't

- Do: `--quick` first; parse stdout JSON; keep prose off stdout.
- Don't: whole-binary dumps; `axt @ sym.imp.*`; feed briefings into a model to pick adapters inside r2b; execute the target.
