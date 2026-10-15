# Plan: r2b MCP server (later)

Status: stub. Not implemented in this change.

## Goal

Expose the same allowlisted verbs as `r2b-exec` over MCP so planners can
call tools without a free-form shell.

## Constraints

- Python 3.12+, packaged with `uv`.
- Tools mirror `r2b.harness.exec_shim.ALLOWED_SUBCOMMANDS` only.
- Analysis path never calls a model; `--ask` / review LLM modes stay
  explicit opt-in tools if exposed at all.
- Never execute analysis targets; no arbitrary `r2` command tool.
- JSON schemas for tool results reuse `schemas/*.schema.json`.

## Sketch

```text
uv init / packages under src/r2b_mcp/ (or src/r2b/mcp/)
tools: env, setup, brief, verify, diff, decompile, records, insights,
       review, bundle.inspect, bundle.create
each tool → r2b.harness.exec_shim.run_allowlisted([...]) or in-process API
```

Ship after the skill + `r2b-exec` shim prove out with omp / Claude Code / Grok.
