"""Host sniff → recommended install flavor.

Flavors (hackable: add a toml under config/flavors/ and a branch here)::

    core  Pi / 8 GB / omp box. r2 + file. No Ghidra, no angr.
    lab   Workstation. r2 extras. Extractors optional. Ghidra only if x86_64.
    full  16 GB+ x86_64. analyzers extra, Ghidra, extract, optional web.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..extract.binwalk3 import find_binwalk3
from ..paths import shipped_config_dir

SCHEMA_VERSION = "r2b.setup.v1"
FLAVORS = ("core", "lab", "full")


@dataclass(slots=True)
class HostFacts:
    os: str
    arch: str
    ram_gb: float
    cpus: int
    python: str
    uv: bool
    docker: bool
    node: bool
    likely_pi: bool
    tools: dict[str, bool] = field(default_factory=dict)


def sniff_host(*, tools: dict[str, bool] | None = None) -> HostFacts:
    arch = platform.machine().lower() or "unknown"
    ram_gb = _ram_gb()
    model = _device_model().lower()
    likely_pi = "raspberry" in model or (arch in {"aarch64", "arm64", "armv7l"} and ram_gb < 12)
    known = tools if tools is not None else _which_tools()
    return HostFacts(
        os=platform.system().lower(),
        arch=arch,
        ram_gb=ram_gb,
        cpus=os.cpu_count() or 1,
        python=platform.python_version(),
        uv=bool(shutil.which("uv")),
        docker=bool(shutil.which("docker")),
        node=bool(shutil.which("node") or shutil.which("npm")),
        likely_pi=likely_pi,
        tools=known,
    )


def recommend_flavor(facts: HostFacts) -> str:
    if facts.ram_gb < 8 or facts.likely_pi:
        return "core"
    if facts.arch in {"x86_64", "amd64"} and facts.ram_gb >= 16:
        return "full"
    return "lab"


def recommend_setup(
    *,
    facts: HostFacts | None = None,
    flavor: str | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    facts = facts or sniff_host()
    chosen = (flavor or recommend_flavor(facts)).strip().lower()
    if chosen not in FLAVORS:
        raise ValueError(f"unknown flavor {chosen!r}; expected one of {FLAVORS}")
    have, missing, skip, apt, extra, overlay, why, notes = _plan_for(chosen, facts)
    commands = _commands(chosen, facts, extra, overlay, apt)
    config_dir = (repo_root / "config") if repo_root is not None else shipped_config_dir()
    overlay_path = config_dir / "flavors" / f"{chosen}.toml"
    if not overlay_path.is_file():
        notes.append(f"overlay {overlay} is missing from the install")
    return {
        "schema_version": SCHEMA_VERSION,
        "flavor": chosen,
        "recommended_flavor": recommend_flavor(facts),
        "why": why,
        "host": {
            "os": facts.os,
            "arch": facts.arch,
            "ram_gb": round(facts.ram_gb, 1),
            "cpus": facts.cpus,
            "python": facts.python,
            "likely_pi": facts.likely_pi,
            "uv": facts.uv,
            "docker": facts.docker,
            "node": facts.node,
        },
        "uv_extra": extra,
        "overlay": overlay,
        "have": have,
        "missing": missing,
        "skip": skip,
        "apt": apt,
        "commands": commands,
        "notes": notes,
        "agent": {
            "json_stdout": True,
            "verbs": ["brief", "analyze", "verify", "decompile", "records", "insights", "env", "setup"],
            "empty_ask_exit": 2,
        },
    }


def _plan_for(
    flavor: str, facts: HostFacts
) -> tuple[list[str], list[dict[str, str]], list[dict[str, str]], list[str], str, str, str, list[str]]:
    have = [name for name, ok in sorted(facts.tools.items()) if ok]
    if facts.uv:
        have.append("uv")
    skip: list[dict[str, str]] = []
    notes: list[str] = []
    apt = ["radare2", "file", "libmagic-dev"]
    overlay = f"config/flavors/{flavor}.toml"

    if flavor == "core":
        extra = "r2"
        why = "Low RAM or ARM lab box — sniff + r2 only. Ghidra/angr would swap or emit empty C."
        skip.append({"name": "angr", "reason": "RAM; core flavor never pulls Unicorn/angr"})
        skip.append({"name": "ghidra", "reason": "headless analysis needs a multi-GB Java heap; core keeps it opt-in"})
        skip.append({"name": "gef", "reason": "Docker optional; not on a Pi"})
        skip.append({"name": "web-ui", "reason": "omp/CLI is the contract; Vite is extra"})
        notes.append("Copy config/openrouter.example.toml into config/local.toml for a model.")
        notes.append("Optional --ask SDKs: uv sync --extra llm (Ollama needs none).")
        notes.append("Merge flavor overlay first so angr/ghidra stay off.")
    elif flavor == "lab":
        extra = "r2"
        why = "Workstation: r2 extras, optional extractors, and opt-in Ghidra/symbolic analysis."
        if facts.os == "linux" and facts.arch not in {"x86_64", "amd64"}:
            skip.append(
                {
                    "name": "ghidra",
                    "reason": f"{facts.os}/{facts.arch} — not auto-installed by the lab flavor; configure an existing distribution explicitly",
                }
            )
        else:
            notes.append("Optional: r2b ghidra setup --version 11.4.2")
        if facts.ram_gb < 12:
            skip.append({"name": "angr", "reason": f"{facts.ram_gb:.0f} GB RAM; keep enable_angr=false"})
        else:
            notes.append("Optional symbolic: uv sync --extra symbolic")
        apt.extend(["binwalk3", "squashfs-tools"])
        if facts.os == "linux":
            apt.append("bubblewrap")
        else:
            skip.append({
                "name": "extractor-isolation",
                "reason": "bubblewrap requires Linux; use a no-egress Linux worker for untrusted extraction",
            })
        notes.append("Extractors stay off until `brief --extract` and fail closed without bubblewrap.")
        notes.append("Optional --ask SDKs: uv sync --extra llm (Ollama needs none).")
    else:
        extra = "analyzers"
        why = "16 GB+ x86_64 — full extra set. Still don't dump whole-binary Ghidra."
        apt.extend(["binwalk3", "squashfs-tools"])
        if facts.os == "linux":
            apt.append("bubblewrap")
        else:
            skip.append({
                "name": "extractor-isolation",
                "reason": "bubblewrap requires Linux; use a no-egress Linux worker for untrusted extraction",
            })
        notes.append("r2b ghidra setup --version 11.4.2 then export GHIDRA_INSTALL_DIR")
        notes.append("Optional --ask SDKs: uv sync --extra llm (Ollama needs none).")
        if facts.node:
            notes.append(
                "Web UI: uv sync --extra web then uv run r2b-web && (cd web/frontend && npm ci && npm run dev)"
            )
        else:
            skip.append({"name": "web-ui", "reason": "node/npm not on PATH"})

    if flavor != "core":
        if not facts.tools.get("binwalk3"):
            notes.append("binwalk3 missing; --extract will skip that tool.")
        if not facts.tools.get("unblob"):
            notes.append("unblob missing; optional.")

    required = ["radare2", "file"]
    missing = [
        {"name": name, "how": _how_to_install(name)}
        for name in required
        if not facts.tools.get(name)
    ]
    if not facts.uv:
        missing.append({"name": "uv", "how": "curl -LsSf https://astral.sh/uv/install.sh | sh"})
    return have, missing, skip, _dedupe(apt), extra, overlay, why, notes


def _commands(
    flavor: str,
    facts: HostFacts,
    extra: str,
    overlay: str,
    apt: list[str],
) -> list[str]:
    cmds: list[str] = []
    if not facts.uv:
        cmds.append("curl -LsSf https://astral.sh/uv/install.sh | sh")
    need_core = [pkg for pkg in ("radare2", "file") if not facts.tools.get(pkg)]
    if facts.os == "darwin" and need_core:
        brew = []
        if "radare2" in need_core:
            brew.append("radare2")
        if "file" in need_core:
            brew.append("libmagic")
        cmds.append("brew install " + " ".join(brew))
    elif facts.os == "linux" and need_core:
        # Optional extractors are reported as notes. Do not make a working
        # core install fail because a distro does not package binwalk3.
        cmds.append("sudo apt-get install -y radare2 file libmagic-dev")
    cmds.append(f"uv sync --extra {extra}")
    cmds.append("uv run r2b env --json")
    notes_cmd = f"# optional overlay (off by default): cp {overlay} config/local.toml"
    cmds.append(notes_cmd)
    return cmds


def _how_to_install(name: str) -> str:
    if name == "radare2":
        return "apt-get install -y radare2  # or brew install radare2"
    if name == "file":
        return "apt-get install -y file libmagic-dev"
    return f"install {name}"


def _which_tools() -> dict[str, bool]:
    names = {
        "radare2": ["radare2", "r2"],
        "file": ["file"],
        "unblob": ["unblob"],
        "bwrap": ["bwrap"],
        "unsquashfs": ["unsquashfs"],
    }
    found: dict[str, bool] = {}
    for name, candidates in names.items():
        found[name] = any(shutil.which(c) for c in candidates)
    found["binwalk3"] = bool(find_binwalk3())
    headless = shutil.which("analyzeHeadless")
    ghidra_run = shutil.which("ghidraRun")
    ghidra_from_run = (
        Path(ghidra_run).resolve().parent / "support" / "analyzeHeadless"
        if ghidra_run
        else None
    )
    configured_ghidra = os.environ.get("GHIDRA_INSTALL_DIR")
    configured_headless = (
        Path(configured_ghidra).expanduser() / "support" / "analyzeHeadless"
        if configured_ghidra
        else None
    )
    found["ghidra"] = bool(
        headless
        or (ghidra_from_run and ghidra_from_run.is_file())
        or (configured_headless and configured_headless.is_file())
    )
    return found


def _ram_gb() -> float:
    try:
        page = os.sysconf("SC_PAGE_SIZE")
        phys = os.sysconf("SC_PHYS_PAGES")
        if page > 0 and phys > 0:
            return (page * phys) / (1024**3)
    except (ValueError, OSError, AttributeError):
        pass
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                kb = float(line.split()[1])
                return kb / (1024**2)
    return 0.0


def _device_model() -> str:
    for path in (Path("/proc/device-tree/model"), Path("/sys/firmware/devicetree/base/model")):
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8", errors="replace").replace("\x00", "")
            except OSError:
                continue
    cpu = Path("/proc/cpuinfo")
    if cpu.is_file():
        try:
            return cpu.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
    return ""


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


__all__ = [
    "FLAVORS",
    "HostFacts",
    "SCHEMA_VERSION",
    "recommend_flavor",
    "recommend_setup",
    "sniff_host",
]
