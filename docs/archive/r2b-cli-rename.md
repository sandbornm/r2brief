# Plan: CLI `r2b` → `r2b`

**DONE** (landed on `feat/root-tidy` / PR #45). CLI is `r2b`; `r2b` is
an alias. Do not re-execute. Out of scope still: PyPI `r2brief`,
`R2B_*` env aliases, moving `~/.cache/r2b`.

Historical plan below. Do **not** rename the Python package,
JSON schemas, or `R2B_*` env vars.

Repo: `sandbornm/r2brief`, branch `feat/triage-packaging` (or a follow-up
branch off it). CLI today: `r2b`. Product name: r2brief. Desired binary:
`r2b`.

## Pain

**Low**, if the scope below is respected.

| Layer | Change? | Why |
|---|---|---|
| `[project.scripts]` `r2b` / `r2b-web` | yes | this is the whole job |
| Docs, help strings, install snippets | yes | what humans type |
| `import r2b` / `src/r2b/` | **no** | hundreds of imports; PyPI module name |
| `r2b.briefing.v1` and other schema ids | **no** | harness contract already shipped in tests |
| `R2B_CONFIG`, `R2B_FLAVOR`, XDG `~/.config/r2b` | **no** | already in people’s `.env`; add `R2B_*` aliases later if needed |
| Wheel filename `r2b-0.1.0-*.whl` | **no** this pass | still `[project].name = "r2b"` until PyPI `r2brief` |

Keep `r2b` and `r2b-web` as aliases on the same functions so old
scripts and CI do not break. One release with both names is enough.

`r2b` is short and sits next to `r2`. It does not collide with the
radare2 binary (`r2`). It does not claim to *be* radare2.

## Do not

- Mass-replace `r2b` in Python. That would rename the library.
- Change `schema_version` strings.
- Rewrite `PRD.md`, `ANALYSIS_SETUP_REVIEW.md`, or `docs/plans/2026-01-27-*`.
- Rename the GitHub repo (already `r2brief`) or the local checkout folder.
- Touch `config/local.toml` or `.env`.

## Code

1. `pyproject.toml` `[project.scripts]`:

```toml
r2b = "r2b.cli:run"
r2b-web = "r2b.web.server:run"
r2b = "r2b.cli:run"
r2b-web = "r2b.web.server:run"
```

2. `src/r2b/cli.py` — user-facing strings that tell you to type `r2b`
   (`ghidra status`, setup next-steps, `uv pip install 'r2b[…]'` stays
   as the **package extra**, not the binary). Binary examples become
   `r2b brief …`. Package extras stay `r2b[r2]`.

3. Scripts that **exec** the CLI (not comments only):

- `scripts/install.sh` — `uv run r2b setup`, smoke `r2b env`, `r2b brief`
- `scripts/setup_backend.sh`
- `scripts/run_backend.sh` — `uv run r2b-web`
- `scripts/dry_run.sh` if it still calls `r2b`

4. Tests: `tests/unit/test_cli_harness.py` still uses `CliRunner` on
   `app`; no argv name there. Add in `tests/unit/test_cli_version.py`:

- `[project.scripts]` contains `r2b` and `r2b-web`
- both point at `r2b.cli:run` / `r2b.web.server:run`
- `r2b` remains as an alias

Optional: `CliRunner` cannot see console_scripts; a one-liner
`uv run r2b --version` in that test (or a subprocess mark) is enough.

5. Frontend: `App.tsx` error string
   `python -m r2b web` → `uv run r2b-web` (that path was already stale).
   Do not rename `localStorage` keys (`r2b-settings`).

## Docs (this is most of the work)

Replace **command examples** `r2b` / `uv run r2b` with `r2b` /
`uv run r2b`, except:

- `import r2b`
- `src/r2b/`
- `r2b.briefing.v1`, `r2b.setup.v1`, …
- `uv pip install 'r2b[r2]'` (package name)
- `--cov=r2b` (coverage source)

Files to edit (command examples + mermaid node labels):

- `README.md`
- `docs/USAGE.md`
- `docs/HARNESS.md`
- `docs/install.md`
- `docs/RELEASE.md`
- `docs/REPORTING.md` (prose “r2b can also export…” → “r2b can also…”)
- `setup.md`
- `AGENTS.md` (CLI verbs in the banner; keep module paths)
- `CLAUDE.md` (quick commands)
- `NOTICE.md` (`r2b-web` → `r2b-web` in the Flask row)
- `config/flavors/*.toml` header comments (`r2b setup --flavor …`)
- `CHANGELOG.md` Unreleased: “CLI binary is `r2b`; `r2b` is an alias.”

Voice: unslop. No “it’s not X, it’s Y.” One sentence at the top of
README/USAGE: `r2b` is the command; `import r2b` is the library.

HARNESS.md table: left column becomes `r2b brief BIN --quick --json`.
Schema column stays `r2b.briefing.v1`.

## Verify

```bash
uv run r2b --version
uv run r2b --version          # alias still works
uv run r2b setup --json
uv run pytest tests/unit/test_cli_version.py tests/unit/test_cli_harness.py
# grep should find almost no *command* examples left:
rg -n 'uv run r2b |`r2b brief|`r2b env|`r2b verify|`r2b-web' README.md docs AGENTS.md CLAUDE.md
```

Allowed leftovers: `import r2b`, schema ids, `r2b[r2]`, coverage, XDG
paths, `R2B_*`.

## Out of scope (later)

- PyPI project `r2brief` and `[project].name`
- Console script `r2brief` as a third alias
- `R2B_CONFIG` alias for `R2B_CONFIG`
- Moving `~/.local/share/r2b`

## Commit

```
feat: ship the CLI as r2b

Keep r2b / r2b-web as aliases. Library import, schema ids, and R2B_*
env vars stay.
```
