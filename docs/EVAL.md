# Evaluation: goldens + agent sanity

## Goldens (`tests/goldens/`)

Pinned, deterministic cases. Each directory has `expected.json` with the
exact JSON fields / exit codes under test (not free text).

| id | What it pins |
|---|---|
| `openwrt_ubusd` | Release-delta shaped like OpenWrt 24.10.3→24.10.4: **109** common files → **3** changed ELFs (`bin/busybox`, `sbin/ubusd`, `usr/sbin/odhcpd`). Synthetic trees under `tree_a/` / `tree_b/`. |
| `asus_cve_2024_3079` | ASUS RT-AX88U CVE-2024-3079: tags (`CWE-121`/`CWE-787`, `TID-327`, `MID-004`, CVE id) + named sink `replace_str` / `sprintf`. |
| `totolink_cwe78` | TOTOLINK CWE-78: tags (`CWE-78`, `TID-310`, `MID-071`) + `system` sink class. |
| `hello` | Tiny shipped `samples/bin/arm64/hello`: briefing schema, verify+tags, missing-file exit `1`, no-model reject `64`, bundle SHA-256 stability. |

Pytest (`tests/unit/test_goldens_r2b_exec.py`) drives **r2b-exec** only (no
model). Commands that need radare2 are skipped when `radare2` is absent.

## Agent sanity (`scripts/agent_sanity/`, opt-in)

Never part of default CI.

```bash
# discover only
uv run python scripts/agent_sanity/run.py --dry-discover

# run against available CLIs (codex / claude / grok)
uv run python scripts/agent_sanity/run.py --out scripts/agent_sanity/results
```

The runner:

1. Puts an allowlisted `r2b-exec` wrapper on `PATH`.
2. Feeds each agent the fixed skill prompt from `docs/skills/r2brief.md`.
3. Scores the transcript + final JSON against the golden `agent_score`:
   - right changed files / sink / import / tags when required
   - stayed on the r2b-exec allowlist
   - no r2b model flags (`--ask`, `--mode llm|both`, `--review-lens`)
   - within step/time bounds
4. Writes `results-<host>.json` and a markdown table. Missing CLIs are
   listed as `missing` and do **not** fail the script.

Do not install or log into agent CLIs from this harness.


## Host inventory (this evaluation)

| host | codex | claude | grok |
|---|---|---|---|
| box | missing | missing | missing |
| Kali | installed (`~/.local/bin`) | installed | installed |
| Fibula | ready | ready | installed, not signed in |
| minimu | ready | ready | ready (auth present) |
| minimo | ready | ready | ready (auth present) |
| minima | ready | ready | missing |

Sanity runs executed on Fibula only (agents ready + repo synced). Missing or
unsigned-in CLIs are reported, never installed or logged in by the harness.
