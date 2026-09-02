# LLM loop on ubusd: r2b in the path, not beside it

Status on 2026-09-02: **two of four models ran**. The machine-readable
result is [`llm-loop-ubusd.json`](llm-loop-ubusd.json).

This is not “which model finds the CVE.” The question is whether a
planner that is *allowed* to use r2b actually uses it, instead of
shelling out to `r2` / Ghidra, when `handoff.next_argv` is empty.

## Frozen input

OpenWrt 24.10.3 `sbin/ubusd` (AArch64), the same ELF as the Kali
release-delta case. `--quick` briefing already saved. Regions:

```text
imports:network   90  lead
entry:entry       89  0x1e18  lead
imports:memory    84  memcpy / sprintf / strcpy  lead
```

`next_argv` is **empty** (no `system`/`popen`/`exec*`). Dangerous
imports still list `strcpy`. Gold from the recorded verify:

```text
0x00004b50  fcn.000033c4  dynamic
0x00004b6c  unknown       dynamic
0x00004ba8  fcn.00004a3c  dynamic   ← event-registration caller
```

Rules review with thesis “put strcpy callers ahead of entry” **does not
reorder**: network, then entry, then memory. Noise labels stay
`needs_confirmation` / `lead`. The model has to read the capsule, not
the auto-queue.

## Protocol

Each agent got the same prompt: only `uv run r2b …`; no raw r2/Ghidra;
empty `next_argv` is not a stop; at most verify + one decompile; ADDR
must come from r2b JSON.

| Agent | How | Result |
|---|---|---|
| rules review | `r2b review --mode rules` | no HTTP; order unchanged |
| Grok 4.6 | `grok --always-approve` headless | **in loop** |
| Codex (`gpt-5.4`) | `codex exec` | **in loop** |
| Kimi K2.5 | `r2b review --mode llm` + `config/kimi.example.toml` | **abstain** — `MOONSHOT_API_KEY` unset |
| GLM 5.1 | `r2b review --mode llm` + `config/glm.example.toml` | **abstain** — `GLM_API_KEY` unset |

## What the two runners did

Both ignored empty `next_argv`, ran the product command, and named all
three gold sites. Neither invoked `r2` or `analyzeHeadless`.

| | Grok 4.6 | Codex gpt-5.4 |
|---|---|---|
| Sidestep raw r2/Ghidra | no | no |
| `r2b verify --import strcpy` | yes | yes |
| Callers | 0x4b50, 0x4b6c, 0x4ba8 | same |
| Then `r2b decompile` | call site `0x4b50` | call site `0x4ba8` |
| Decompile success | false (`no function at` call site) | false (Ghidra project lock / no function) |

r2b changed the path: they did not `axt @ sym.imp.strcpy`. They also
decompiled a **call site**, not `fcn.00004a3c` (`0x4a3c`). `verify`
JSON names the containing function, but the address field is the call.
That is a product gap, not a model miss.

## Demo claim

The working website story is: **brief this `ubusd`, empty `next_argv`,
memory capsule still lists `strcpy`, the planner that stays on r2b
runs `verify --import strcpy` and gets three dynamic callers.** Rules
review alone does not queue that command. Kimi/GLM are wired as
overlays and were not run here because the keys are absent.

Do not present this as a four-way quality bake-off until those two
keys exist and the decompile target is the containing function VA.
