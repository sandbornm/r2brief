"""Environment detection and verification."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..config import AppConfig, apply_lab_tool_path
from ..extract.binwalk3 import find_binwalk3
from ..llm.credentials import resolve_llm_api_key, resolve_provider_base_url, unused_glm_key_hint
from .ghidra import GhidraDetection, detect_ghidra


@dataclass(slots=True)
class ToolCheck:
    name: str
    command: str | None
    available: bool
    version: str | None = None
    path: Path | None = None
    details: str | None = None



@dataclass(slots=True)
class LLMCheck:
    provider: str
    model: str
    api_key_env: str | None
    api_key_present: bool
    base_url: str | None = None
    hint: str | None = None


@dataclass(slots=True)
class EnvironmentReport:
    python_version: str
    uv_available: bool
    openai_key_present: bool
    tools: list[ToolCheck] = field(default_factory=list)
    ghidra: GhidraDetection | None = None
    llm: LLMCheck | None = None
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def missing_tools(self) -> list[str]:
        return [t.name for t in self.tools if not t.available]


_COMMANDS: dict[str, list[str]] = {
    "radare2": ["radare2", "r2"],
    "ghidra": ["ghidraRun", "analyzeHeadless"],
    "docker": ["docker"],
    "ollama": ["ollama"],
    "file": ["file"],
    "binwalk": ["binwalk"],
    "binwalk3": ["binwalk3"],
    "unblob": ["unblob"],
    "bwrap": ["bwrap"],
    "unsquashfs": ["unsquashfs"],
    "sasquatch": ["sasquatch"],
    "qemu-user": ["qemu-aarch64", "qemu-arm", "qemu-x86_64"],
    "qemu": ["qemu-system-x86_64", "qemu-system-aarch64"],
    "frida": ["frida-server", "frida"],
    "checksec": ["checksec"],
    "jefferson": ["jefferson"],
    "ubireader": ["ubireader_extract_files", "ubireader_list_files"],
}


def _check_command(name: str, candidates: Iterable[str]) -> ToolCheck:
    for candidate in candidates:
        path = shutil.which(candidate)
        if not path:
            continue
        version = _probe_version(candidate)
        return ToolCheck(name=name, command=candidate, available=True, version=version, path=Path(path))
    return ToolCheck(name=name, command=None, available=False)


def _check_binwalk3() -> ToolCheck:
    path_text = find_binwalk3()
    if not path_text:
        return ToolCheck(name="binwalk3", command=None, available=False)
    path = Path(path_text)
    return ToolCheck(
        name="binwalk3",
        command=path.name,
        available=True,
        version=_probe_version(path_text),
        path=path,
    )


def _probe_version(command: str) -> str | None:
    try:
        output = subprocess.check_output([command, "--version"], stderr=subprocess.STDOUT, timeout=4)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return output.decode().splitlines()[0].strip()


def _check_python_module(module: str) -> ToolCheck:
    try:
        __import__(module)
    except ModuleNotFoundError:
        return ToolCheck(name=module, command=module, available=False)
    except Exception as exc:
        # Handle import errors from broken dependencies (e.g. angr + msgspec mismatch)
        return ToolCheck(
            name=module,
            command=module,
            available=False,
            details=f"Import failed: {type(exc).__name__}: {exc}",
        )
    return ToolCheck(name=module, command=module, available=True)



def detect_environment(config: AppConfig) -> EnvironmentReport:
    apply_lab_tool_path()
    key, key_env = resolve_llm_api_key(config)
    key_present = bool(key)
    report = EnvironmentReport(
        python_version=sys.version.split()[0],
        uv_available=shutil.which("uv") is not None,
        openai_key_present=key_present,
        llm=LLMCheck(
            provider=config.llm.provider,
            model=config.llm.model,
            api_key_env=key_env,
            api_key_present=key_present,
            base_url=resolve_provider_base_url(config, key_env),
            hint=unused_glm_key_hint(config),
        ),
    )
    if config.analysis.require_elf:
        report.notes.append(
            "analysis.require_elf=true; firmware blobs will be rejected. "
            "Set require_elf=false in config/local.toml for this lab."
        )
    report.tools.append(_check_command("radare2", _COMMANDS["radare2"]))
    report.tools.append(_check_command("docker", _COMMANDS["docker"]))
    if config.llm.provider.lower() in {"ollama", "local"} or (
        config.llm.enable_fallback and (config.llm.fallback_provider or "").lower() in {"ollama", "local"}
    ):
        report.tools.append(_check_command("ollama", _COMMANDS["ollama"]))
    report.tools.append(_check_python_module("r2pipe"))
    report.tools.append(_check_python_module("capstone"))
    if config.analysis.enable_angr:
        report.tools.append(_check_python_module("angr"))
    if config.llm.provider.lower() in {"anthropic", "claude"} or (
        config.llm.enable_fallback and (config.llm.fallback_provider or "").lower() in {"anthropic", "claude"}
    ):
        report.tools.append(_check_python_module("anthropic"))

    # Optional runtime tools helpful for replay/debugging.
    report.tools.append(_check_command("file", _COMMANDS["file"]))
    report.tools.append(_check_command("binwalk", _COMMANDS["binwalk"]))
    report.tools.append(_check_binwalk3())
    report.tools.append(_check_command("unblob", _COMMANDS["unblob"]))
    report.tools.append(_check_command("bwrap", _COMMANDS["bwrap"]))
    report.tools.append(_check_command("unsquashfs", _COMMANDS["unsquashfs"]))
    report.tools.append(_check_command("sasquatch", _COMMANDS["sasquatch"]))
    report.tools.append(_check_command("qemu-user", _COMMANDS["qemu-user"]))
    report.tools.append(_check_command("qemu", _COMMANDS["qemu"]))
    report.tools.append(_check_command("frida", _COMMANDS["frida"]))
    report.tools.append(_check_command("checksec", _COMMANDS["checksec"]))
    report.tools.append(_check_command("jefferson", _COMMANDS["jefferson"]))
    report.tools.append(_check_command("ubireader", _COMMANDS["ubireader"]))

    ghidra_detection = detect_ghidra(config)
    report.ghidra = ghidra_detection
    report.notes.extend(ghidra_detection.notes)
    report.issues.extend(ghidra_detection.issues)

    optional_tools = {
        "ollama",
        "qemu",
        "qemu-user",
        "frida",
        "checksec",
        "jefferson",
        "ubireader",
        "binwalk",
        "binwalk3",
        "unblob",
        "bwrap",
        "unsquashfs",
        "sasquatch",
    }
    for tool in report.tools:
        if not tool.available:
            if tool.name == "ollama":
                report.notes.append(
                    "Optional Ollama host missing; deterministic analysis still works without --ask."
                )
            elif tool.name in optional_tools:
                report.notes.append(f"Optional tool missing: {tool.name}")
            else:
                report.issues.append(f"Missing dependency: {tool.name}")

    have_bwrap = any(tool.name == "bwrap" and tool.available for tool in report.tools)
    if config.extract.enable and not have_bwrap:
        if config.extract.allow_unsafe_fallback:
            report.issues.append(
                "UNSAFE extraction fallback enabled: external extractors may retain host and network access."
            )
        else:
            report.notes.append(
                "External extraction will fail closed because bubblewrap is unavailable."
            )

    if not report.uv_available:
        report.issues.append("uv package manager not found on PATH.")

    if config.llm.provider.lower() not in {"ollama", "local"} and not report.openai_key_present:
        report.notes.append(
            f"Environment variable {key_env or config.llm.api_key_env} not detected; "
            "LLM --ask will fail until set (analyze without --ask still works)."
        )
    if report.llm and report.llm.hint:
        report.notes.append(report.llm.hint)
    if config.llm.enable_fallback and config.llm.fallback_api_key_env:
        if config.llm.fallback_api_key_env not in os.environ:
            report.notes.append(
                f"Fallback LLM key {config.llm.fallback_api_key_env} not detected; fallback provider disabled."
            )

    return report


__all__ = [
    "EnvironmentReport",
    "LLMCheck",
    "ToolCheck",
    "detect_environment",
]
