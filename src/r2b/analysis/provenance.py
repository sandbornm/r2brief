"""Portable provenance and replay recipes for one analysis run.

This is deliberately independent of the trajectory database.  A result carries
enough information to answer which adapters produced each evidence bag, which
configuration gates were active, and how to repeat the analysis against the
same input bytes.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from ..config import AppConfig
    from .orchestrator import AnalysisResult


PROVENANCE_SCHEMA_VERSION = "r2b.provenance.v1"
INPUT_TOKEN = "{input}"

_QUICK_ORDER = (
    "sniff",
    "binary_format",
    "autoprofile",
    "firmware",
    "libmagic",
    "runtime",
    "radare2",
    "artifact_dag",
)
_DEEP_ORDER = (
    "radare2",
    "capstone",
    "dwarf",
    "ghidra",
    "angr",
    "frida",
    "gef",
    "firmware_children",
)
_QUICK_ALIASES = frozenset({"identification", "readelf", "packer"})


def sha256_path(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Return the SHA-256 of ``path`` without loading the whole file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_analysis_provenance(
    result: AnalysisResult,
    config: AppConfig | None = None,
) -> dict[str, Any]:
    """Build a small deterministic recipe from an in-memory analysis result.

    Adapter payloads stay in ``quick_scan``/``deep_scan``.  Provenance points to
    those bags with JSON pointers and records a canonical digest, so an export
    can prove which evidence was used without duplicating large disassembly or
    decompiler output.
    """
    binary = Path(result.binary).expanduser().resolve()
    digest = _input_digest(result, binary)
    plan = asdict(result.plan) if result.plan is not None else {}
    actions = _ordered_actions(result)
    adapter_status = _adapter_status(result, actions)
    argv = _replay_argv(plan, config)
    safe_config = _safe_config(config)
    provenance: dict[str, Any] = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "producer": {"name": "r2b", "version": _package_version()},
        "input": {
            "path": str(binary),
            "name": binary.name,
            "size_bytes": binary.stat().st_size if binary.is_file() else None,
            "sha256": digest,
        },
        "plan": plan,
        "config": safe_config,
        "adapter_status": adapter_status,
        "actions": actions,
        "replay": {
            "input_token": INPUT_TOKEN,
            "expected_sha256": digest,
            "argv": argv,
            "shell": render_replay_shell(argv),
            "shell_uses_current_config": bool(safe_config),
        },
    }
    replay = provenance["replay"]
    assert isinstance(replay, dict)  # built directly above; narrows static type
    replay["python"] = render_replay_python(provenance)
    return provenance


def render_replay_shell(
    provenance_or_argv: Mapping[str, Any] | list[str],
    *,
    input_path: str | Path | None = None,
) -> str:
    """Render a one-line, copyable command from provenance or recipe argv."""
    if isinstance(provenance_or_argv, Mapping):
        replay = provenance_or_argv.get("replay")
        replay_dict = replay if isinstance(replay, Mapping) else {}
        raw_argv = replay_dict.get("argv")
        argv = [str(item) for item in raw_argv] if isinstance(raw_argv, list) else []
    else:
        argv = [str(item) for item in provenance_or_argv]
    replacement = str(input_path) if input_path is not None else "$R2B_INPUT"
    rendered: list[str] = []
    for item in argv:
        if item == INPUT_TOKEN and input_path is None:
            # Keep the shell variable expandable while quoting paths with spaces.
            rendered.append('"$R2B_INPUT"')
        else:
            rendered.append(shlex.quote(replacement if item == INPUT_TOKEN else item))
    return " ".join(rendered)


def render_replay_python(
    provenance: Mapping[str, Any],
    *,
    input_path: str | Path | None = None,
) -> str:
    """Render a standalone Python recipe using only the public r2b API."""
    input_info = provenance.get("input")
    input_dict = input_info if isinstance(input_info, Mapping) else {}
    plan_info = provenance.get("plan")
    plan = plan_info if isinstance(plan_info, Mapping) else {}
    config_info = provenance.get("config")
    config = config_info if isinstance(config_info, Mapping) else {}
    extract_info = config.get("extract")
    extract = extract_info if isinstance(extract_info, Mapping) else {}
    profile = str(plan.get("profile") or ("standard" if plan.get("deep") else "triage"))
    original = str(input_dict.get("path") or "sample.bin")
    expected = str(input_dict.get("sha256") or "")
    lines = [
        "import os",
        "from pathlib import Path",
        "from r2b import AnalysisOptions, analyze",
        "from r2b.config import AppConfig",
        "",
    ]
    if input_path is None:
        lines.append(f"binary = Path(os.environ.get('R2B_INPUT', {original!r}))")
    else:
        lines.append(f"binary = Path({str(input_path)!r})")
    lines.extend(
        (
            f"expected_sha256 = {expected!r}",
            f"config = AppConfig.model_validate({dict(config)!r})",
            "report = analyze(",
            "    binary,",
            "    config=config,",
            "    options=AnalysisOptions(",
            f"        profile={profile!r},",
            f"        extract={bool(extract.get('enable'))!r},",
            "    ),",
            ")",
            "assert report.payload['provenance']['input']['sha256'] == expected_sha256",
            "print(report.briefing['summary'])",
            "",
        )
    )
    return "\n".join(lines)


def _ordered_actions(result: AnalysisResult) -> list[dict[str, Any]]:
    quick = result.quick_scan if isinstance(result.quick_scan, dict) else {}
    deep = result.deep_scan if isinstance(result.deep_scan, dict) else {}
    status_map = result.tool_status if isinstance(result.tool_status, dict) else {}
    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    quick_names = [*(_name for _name in _QUICK_ORDER if _name in quick)]
    quick_names.extend(sorted(set(quick) - set(quick_names) - _QUICK_ALIASES))
    for name in quick_names:
        payload = quick.get(name)
        if not isinstance(payload, (dict, list)):
            continue
        actions.append(_action(name, "quick", payload, status_map, len(actions) + 1))
        seen.add(("quick", name))

    deep_names = [*(_name for _name in _DEEP_ORDER if _name in deep)]
    deep_names.extend(sorted(set(deep) - set(deep_names)))
    for name in deep_names:
        payload = deep.get(name)
        if not isinstance(payload, (dict, list)):
            continue
        actions.append(_action(name, "deep", payload, status_map, len(actions) + 1))
        seen.add(("deep", name))

    # Failed/skipped adapters may not have an output bag.  Preserve them as
    # status-only steps so "how did this run?" includes tool gaps.
    missing: list[tuple[str, str, dict[str, Any]]] = []
    for name, raw_status in status_map.items():
        if not isinstance(raw_status, dict):
            continue
        stage = str(raw_status.get("stage") or ("quick" if name in _QUICK_ORDER else "deep"))
        if (stage, name) not in seen:
            missing.append((stage, str(name), raw_status))
    stage_rank = {"quick": 0, "deep": 1}
    missing.sort(key=lambda row: (stage_rank.get(row[0], 2), _order_index(row[0], row[1]), row[1]))
    for stage, name, raw_status in missing:
        actions.append(
            {
                "sequence": len(actions) + 1,
                "action": _action_name(name, stage, None),
                "adapter": name,
                "stage": stage,
                "status": str(raw_status.get("status") or "unknown"),
                "result_ref": None,
                "output_sha256": None,
                "summary": _status_summary(raw_status),
            }
        )
    return actions


def _action(
    name: str,
    stage: str,
    payload: dict[str, Any] | list[Any],
    status_map: dict[str, Any],
    sequence: int,
) -> dict[str, Any]:
    status_info = status_map.get(name)
    status = status_info if isinstance(status_info, dict) else {}
    payload_status = payload.get("status") if isinstance(payload, dict) else None
    skipped = bool(payload.get("skipped")) if isinstance(payload, dict) else False
    status_matches_stage = status.get("stage") in {None, stage}
    status_value = status.get("status") if status_matches_stage else None
    normalized_status = "skipped" if skipped else str(payload_status or status_value or "completed")
    return {
        "sequence": sequence,
        "action": _action_name(name, stage, payload),
        "adapter": name,
        "stage": stage,
        "status": normalized_status,
        "result_ref": f"/{stage}_scan/{_json_pointer_token(name)}",
        "output_sha256": _canonical_digest(payload),
        "summary": _payload_summary(payload, status),
    }


def _adapter_status(result: AnalysisResult, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    availability = result.tool_availability if isinstance(result.tool_availability, dict) else {}
    names = set(str(name) for name in availability)
    names.update(str(action["adapter"]) for action in actions)
    rank = {name: index for index, name in enumerate((*_QUICK_ORDER, *_DEEP_ORDER))}
    rows: list[dict[str, Any]] = []
    for name in sorted(names, key=lambda item: (rank.get(item, 999), item)):
        matching = [action for action in actions if action["adapter"] == name]
        rows.append(
            {
                "adapter": name,
                "available": availability.get(name),
                "actions": [int(action["sequence"]) for action in matching],
                "status": matching[-1]["status"] if matching else "not_run",
            }
        )
    return rows


def _replay_argv(plan: Mapping[str, Any], config: AppConfig | None) -> list[str]:
    argv = ["r2b", "brief", INPUT_TOKEN]
    argv.append("--deep" if bool(plan.get("deep")) else "--quick")
    if config is not None and bool(config.extract.enable):
        argv.append("--extract")
    argv.extend(("--no-save", "--json"))
    return argv


def _safe_config(config: AppConfig | None) -> dict[str, Any]:
    if config is None:
        return {}
    # Analysis provenance never needs LLM or storage settings.  Whitelisting
    # also guarantees that an exported recipe cannot leak an API key or secret.
    return {
        "analysis": {
            "enable_angr": config.analysis.enable_angr,
            "enable_ghidra": config.analysis.enable_ghidra,
            "enable_frida": config.analysis.enable_frida,
            "enable_gef": config.analysis.enable_gef,
            "gef_timeout": config.analysis.gef_timeout,
            "gef_max_instructions": config.analysis.gef_max_instructions,
            "require_elf": config.analysis.require_elf,
        },
        "extract": {
            "enable": config.extract.enable,
            "extract_elf": config.extract.extract_elf,
            "timeout_s": config.extract.timeout_s,
            "max_files": config.extract.max_files,
            "max_bytes": config.extract.max_bytes,
            "max_depth": config.extract.max_depth,
        },
        "performance": {"parallel_functions": config.performance.parallel_functions},
        "ghidra": {
            "use_bridge": config.ghidra.use_bridge,
            "max_decompile_functions": config.ghidra.max_decompile_functions,
            "max_types": config.ghidra.max_types,
            "max_strings": config.ghidra.max_strings,
        },
    }


def _input_digest(result: AnalysisResult, binary: Path) -> str:
    quick = result.quick_scan if isinstance(result.quick_scan, dict) else {}
    artifact_dag = quick.get("artifact_dag")
    if isinstance(artifact_dag, dict):
        existing = artifact_dag.get("sha256")
        if isinstance(existing, str) and len(existing) == 64:
            return existing.lower()
    return sha256_path(binary) if binary.is_file() else ""


def _canonical_digest(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _payload_summary(payload: dict[str, Any] | list[Any], status: Mapping[str, Any]) -> dict[str, Any]:
    summary = _status_summary(status)
    if isinstance(payload, list):
        summary["items"] = len(payload)
        return summary
    summary["keys"] = sorted(str(key) for key in payload)[:16]
    for key in ("function_count", "artifact_count", "node_count", "edge_count"):
        value = payload.get(key)
        if isinstance(value, (int, float)):
            summary[key] = value
    return summary


def _status_summary(status: Mapping[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in (
        "duration_ms",
        "elapsed_ms",
        "functions_count",
        "cfg_nodes",
        "cfg_edges",
        "reason",
        "error",
    ):
        value = status.get(key)
        if value not in (None, "", [], {}):
            summary[key] = value
    return summary


def _json_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _order_index(stage: str, name: str) -> int:
    order = _QUICK_ORDER if stage == "quick" else _DEEP_ORDER
    try:
        return order.index(name)
    except ValueError:
        return len(order)


def _action_name(name: str, stage: str, payload: Mapping[str, Any] | list[Any] | None) -> str:
    if name == "artifact_dag":
        return "artifact_dag.build"
    skipped = isinstance(payload, Mapping) and bool(payload.get("skipped"))
    if skipped:
        return f"{name}.skipped"
    if name == "firmware_children":
        return "firmware_children.fanout"
    return f"{name}.{stage}"


def _package_version() -> str:
    try:
        return version("r2b")
    except PackageNotFoundError:  # pragma: no cover - editable checkout without metadata
        return "0.1.0"


__all__ = [
    "INPUT_TOKEN",
    "PROVENANCE_SCHEMA_VERSION",
    "build_analysis_provenance",
    "render_replay_python",
    "render_replay_shell",
    "sha256_path",
]
