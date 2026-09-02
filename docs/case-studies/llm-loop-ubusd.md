# LLM loop on ubusd: r2b in the path, not beside it

Status on 2026-09-02: **four of four models ran**. The machine-readable
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

Grok and Codex had a full shell and still stayed on r2b. This host has
no Kimi or GLM agent CLI, so those two got one host-owned tool,
`run_r2b`, that can only exec `uv run r2b`. That is stricter, not a
sidestep. `review --mode llm` is a different slot: it reorders known
region IDs and cannot run `verify`.

| Agent | How | Result |
|---|---|---|
| rules review | `r2b review --mode rules` | no HTTP; order unchanged |
| Grok 4.6 | `grok --always-approve` headless | **in loop** |
| Codex (`gpt-5.4`) | `codex exec` | **in loop** |
| Kimi K3 | allowlisted `run_r2b` + `config/kimi.example.toml` | **in loop** |
| GLM 5.1 overlay (`glm-5.3`) | allowlisted `run_r2b` + `config/z.ai-coding.example.toml` | **in loop** |

## What the four runners did

All four ignored empty `next_argv`, ran the product command, and named
all three gold sites. None invoked `r2` or `analyzeHeadless`.

| | Grok 4.6 | Codex gpt-5.4 | Kimi K3 | GLM `glm-5.3` |
|---|---|---|---|---|
| Sidestep raw r2/Ghidra | no | no | no | no |
| `r2b verify --import strcpy` | yes | yes | yes | yes |
| Callers | 0x4b50, 0x4b6c, 0x4ba8 | same | same | same |
| Then `r2b decompile` | call site `0x4b50` | call site `0x4ba8` | r2 fn `0x33c4` | r2 fn `0x33c4` |
| Decompile success | false (`no function at` call site) | false (Ghidra lock / no function) | false (`no function at 33c4`) | false (`no function at 33c4`) |

r2b changed the path: they did not `axt @ sym.imp.strcpy`. Grok and
Codex decompiled a **call site**. Kimi and GLM used the verify
`function` field (`000033c4` → `0x33c4`). Neither is
`fcn.00004a3c` (`0x4a3c`). Ghidra still said no function. That was a
product gap, not a model miss: verify now emits `function_addr` (the
containing-function VA) and `r2b decompile BIN ADDR` resolves a call
site to that function.

The GLM key is a Z.ai coding-plan key. `config/glm.example.toml`
(China `open.bigmodel.cn`) and Z.ai `/api/paas/v4` both return 1113.
`config/z.ai-coding.example.toml` is the overlay that actually
answers. Kimi `kimi-k3` pins temperature to 1.0 and needs
`max_tokens >= 16384` so thinking does not eat the answer.

## Demo claim

The working website story is: **brief this `ubusd`, empty `next_argv`,
memory capsule still lists `strcpy`, the planner that stays on r2b
runs `verify --import strcpy` and gets three dynamic callers.** Rules
review alone does not queue that command.

Do not present this as a four-way quality bake-off. The recorded
decompiles used call sites / r2 names. A later live check of
`r2b decompile … 0x4ba8` now returns Ghidra `FUN_00104a3c` at
`0x00104a3c` (`success: true`).
