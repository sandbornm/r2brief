# Notices

r2brief is MIT (`LICENSE`). CLI is `r2b`; library is `r2b`. This file
is the third-party map. We do not vendor radare2, Ghidra, binwalk, or
unblob — r2b wraps them when present. The `r2` prefix means this
process talks to radare2 (like r2pipe / r2ghidra). Not an official
radare2 project.

## Credits

These are the tools a brief actually uses or can call. Names and
licenses are upstream’s.

| Project | Who | License | Where |
|---|---|---|---|
| [radare2](https://rada.re) | pancake (Sergi Alvarez) and the r2 community | LGPL-3.0 | core: metadata, CFG, `verify` |
| [r2pipe](https://github.com/radareorg/radare2-r2pipe) | radareorg | MIT | extra `r2` |
| [Capstone](https://www.capstone-engine.org) | Nguyen Anh Quynh and contributors | BSD | extra `r2` |
| [file](https://www.darwinsys.com/file/) / libmagic | Ian Darwin, Christos Zoulas | BSD | identify |
| [Ghidra](https://ghidra-sre.org) | NSA | Apache-2.0 | `decompile`; not bundled |
| [ghidra_bridge](https://github.com/justfoxing/ghidra_bridge) | justfoxing | MIT | extra `ghidra` |
| [binwalk](https://github.com/ReFirmLabs/binwalk) | ReFirmLabs / binwalk3 | MIT | `--extract` |
| [unblob](https://unblob.org) | ONEKEY | MIT | `--extract` |
| [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) | horsicq and contributors | MIT | optional `diec` host CLI; identification |
| [capa](https://github.com/mandiant/capa) | Mandiant FLARE / Google and contributors | Apache-2.0 | optional host CLI; capability rules |
| squashfs-tools | squashfs-tools authors | GPL | `--extract` |
| bubblewrap | containers/bubblewrap | LGPL-2.0 | extract sandbox |
| [angr](https://angr.io) | angr team | BSD-2 | extra `symbolic` |
| [Unicorn](https://www.unicorn-engine.org) | Nguyen Anh Quynh and contributors | GPLv2 | extra `symbolic` |
| [Frida](https://frida.re) | Ole André Vadla Ravnås and contributors | wxWindows / MIT | extra `dynamic` |
| [GEF](https://hugsy.github.io/gef/) | hugsy and contributors | MIT | Docker traces |
| [Ollama](https://ollama.com) | Ollama | MIT | default `--ask` host |
| [OpenAI Python SDK](https://github.com/openai/openai-python) | OpenAI | Apache-2.0 | extra `llm`; Chat Completions wire |
| [Anthropic SDK](https://github.com/anthropics/anthropic-sdk-python) | Anthropic | MIT | extra `llm`; Messages API |
| [Typer](https://github.com/fastapi/typer) / [Rich](https://github.com/Textualize/rich) / [Pydantic](https://github.com/pydantic/pydantic) | those projects | MIT | CLI |
| [Flask](https://flask.palletsprojects.com) | Pallets | BSD-3 | extra `web` |
| [React](https://react.dev) / [MUI](https://mui.com) / [Vite](https://vitejs.dev) | those projects | MIT | web UI |
| [Geist](https://vercel.com/font) / [IBM Plex](https://github.com/IBM/plex) | Vercel / IBM | OFL | web fonts |

pyelftools is public domain (Eli Bendersky). sqlite-utils and SQLAlchemy
are MIT (Simon Willison / SQLAlchemy authors). python-dotenv is BSD.

Transitive wheels keep their own licenses inside the venv. `r2b setup
--json` lists what is present vs skipped.

## Python (installed by `uv sync`)

Declared in `pyproject.toml`. Typical licenses of the direct set:

| Package | Role | License (upstream) |
|---|---|---|
| typer, rich, pydantic, httpx, python-dotenv | CLI / config (required) | MIT |
| sqlalchemy, sqlite-utils | records / chat (required) | MIT |
| pyelftools | ELF parse (required) | Public domain |
| openai, anthropic | extra `llm` (`--ask` / Chat) | Apache-2.0 / MIT |
| Flask, flask-cors | extra `web` (`r2b-web`) | BSD-3 |
| r2pipe, capstone, python-magic | extra `r2` | MIT / BSD / LGPL-2.1 (libmagic) |
| angr, unicorn | extra `symbolic` | BSD-2 |
| frida, frida-tools | extra `dynamic` | wxWindows / MIT |
| ghidra-bridge | extra `ghidra` (PyPI) | MIT |

Checkout `uv sync` installs extra `std` (r2 + web + llm) via the `dev`
group. A wheel stays CLI-only until `uv pip install 'r2b[r2]'` or
`'r2b[std]'`.
