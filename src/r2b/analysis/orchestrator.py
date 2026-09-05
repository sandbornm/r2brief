"""Analysis orchestration pipeline."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, cast

from ..config import AppConfig
from ..environment import EnvironmentReport
from ..storage.dao import TrajectoryDAO
from ..storage.models import AnalysisTrajectory, TrajectoryAction
from .resource_tree import BinaryResource, FunctionResource, Resource
from .runtime_requirements import get_runtime_requirements
from .sniff import sniff_binary
from .artifact_dag import build_artifact_dag, compact_dag, dump_dag
from .graph import build_analysis_graph
from ..extract.sandbox import ExtractLimits
from ..adapters.base import AdapterRegistry, AdapterUnavailable, AnalyzerAdapter
from ..adapters.triage import CapaAdapter, DetectItEasyAdapter
from ..adapters import (
    AngrAdapter,
    AutoProfileAdapter,
    BinaryFormatAdapter,
    CapstoneAdapter,
    DWARFAdapter,
    FirmwareAdapter,
    FridaAdapter,
    GEFAdapter,
    GhidraAdapter,
    LibmagicAdapter,
    Radare2Adapter,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AnalysisPlan:
    quick: bool = True
    deep: bool = True
    run_angr: bool = False
    persist_trajectory: bool = True
    profile: str = "standard"


@dataclass(slots=True)
class AnalysisResult:
    binary: Path
    plan: AnalysisPlan
    trajectory_id: str | None = None
    resource_tree: Resource | None = None
    quick_scan: dict[str, Any] = field(default_factory=dict)
    deep_scan: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    tool_availability: dict[str, bool] = field(default_factory=dict)  # Which tools were available
    tool_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_coverage: dict[str, Any] = field(default_factory=dict)
    analysis_graph: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)


class AnalysisOrchestrator:
    """Coordinate analysis adapters according to plan."""

    def __init__(
        self,
        config: AppConfig,
        env: EnvironmentReport,
        trajectory_dao: TrajectoryDAO | None = None,
    ) -> None:
        self._config = config
        self._env = env
        self._trajectory_dao = trajectory_dao

        adapters: list[AnalyzerAdapter] = []
        # AutoProfile runs first for quick characterization
        adapters.append(cast(AnalyzerAdapter, BinaryFormatAdapter()))
        adapters.append(cast(AnalyzerAdapter, AutoProfileAdapter()))
        adapters.append(cast(AnalyzerAdapter, FirmwareAdapter(
            artifacts_dir=config.output.artifacts_dir / "firmware",
            enable_carving=config.extract.enable,
            max_total_carve_bytes=config.extract.max_bytes,
            max_carved_files=config.extract.max_files,
        )))
        adapters.append(cast(AnalyzerAdapter, LibmagicAdapter()))
        adapters.append(cast(AnalyzerAdapter, Radare2Adapter()))
        adapters.append(cast(AnalyzerAdapter, CapstoneAdapter()))
        adapters.append(cast(AnalyzerAdapter, DWARFAdapter()))
        adapters.append(DetectItEasyAdapter(timeout_s=config.analysis.die_timeout_s))
        adapters.append(CapaAdapter(
            timeout_s=config.analysis.capa_timeout_s,
            rules_path=config.analysis.capa_rules_path,
        ))

        if config.analysis.enable_ghidra and env.ghidra:
            adapters.append(cast(AnalyzerAdapter, GhidraAdapter(
                detection=env.ghidra,
                project_dir=config.ghidra.project_dir,
                settings=config.ghidra,
            )))
        if config.analysis.enable_angr:
            adapters.append(cast(AnalyzerAdapter, AngrAdapter()))
        if config.analysis.enable_frida:
            adapters.append(cast(AnalyzerAdapter, FridaAdapter()))
        if config.analysis.enable_gef:
            adapters.append(cast(AnalyzerAdapter, GEFAdapter(
                timeout=config.analysis.gef_timeout,
                max_instructions=config.analysis.gef_max_instructions,
            )))

        self._registry = AdapterRegistry(adapters)

    def create_plan(
        self,
        *,
        quick_only: bool = False,
        skip_deep: bool = False,
        profile: str | None = None,
    ) -> AnalysisPlan:
        normalized_profile = (profile or ("triage" if quick_only else "standard")).strip().lower()
        if normalized_profile not in {"triage", "standard", "exhaustive"}:
            normalized_profile = "standard"
        plan = AnalysisPlan(profile=normalized_profile)
        if quick_only or normalized_profile == "triage":
            plan.deep = False
        if skip_deep:
            plan.deep = False
        plan.run_angr = self._config.analysis.enable_angr and plan.deep
        if normalized_profile == "exhaustive":
            plan.deep = True
            plan.run_angr = self._config.analysis.enable_angr
        plan.persist_trajectory = self._config.analysis.enable_trajectory_recording
        return plan

    def analyze(
        self,
        binary: Path,
        plan: AnalysisPlan | None = None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> AnalysisResult:
        plan = plan or self.create_plan()
        binary = binary.resolve()
        if self._config.analysis.require_elf:
            self._ensure_elf(binary)
        result = AnalysisResult(binary=binary, plan=plan)

        # Collect tool availability info for transparency
        for adapter in self._registry:
            try:
                result.tool_availability[adapter.name] = adapter.is_available()
            except Exception:
                result.tool_availability[adapter.name] = False

        self._emit_progress(
            progress_callback,
            "analysis_started",
            {"binary": str(binary), "plan": asdict(plan)},
        )

        trajectory: AnalysisTrajectory | None = None
        if plan.persist_trajectory and self._trajectory_dao:
            trajectory = self._trajectory_dao.start_trajectory(binary)
            result.trajectory_id = trajectory.trajectory_id
            _LOGGER.debug("Trajectory %s started", trajectory.trajectory_id)

        try:
            self._run_quick(binary, result, trajectory, progress_callback)
            if plan.deep:
                self._run_deep(binary, result, trajectory, progress_callback, plan)
            if not result.evidence_coverage:
                result.evidence_coverage = self._build_evidence_coverage(result)
            if not result.analysis_graph:
                result.analysis_graph = build_analysis_graph(result)
            from .provenance import build_analysis_provenance

            result.provenance = build_analysis_provenance(result, self._config)
        finally:
            if trajectory and self._trajectory_dao:
                self._trajectory_dao.finish_trajectory(trajectory)

        self._emit_progress(
            progress_callback,
            "analysis_completed",
            {
                "binary": str(binary),
                "issues": result.issues,
                "notes": result.notes,
            },
        )

        return result

    def _run_quick(
        self,
        binary: Path,
        result: AnalysisResult,
        trajectory: AnalysisTrajectory | None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None,
    ) -> None:
        _LOGGER.info("Starting quick scan: %s", binary)
        self._emit_progress(progress_callback, "stage_started", {"stage": "quick"})

        autoprofile = self._registry.get("autoprofile") if self._has_adapter("autoprofile") else None
        binary_format = self._registry.get("binary_format") if self._has_adapter("binary_format") else None
        firmware = self._registry.get("firmware") if self._has_adapter("firmware") else None
        libmagic = self._registry.get("libmagic") if self._has_adapter("libmagic") else None
        radare = self._registry.get("radare2") if self._has_adapter("radare2") else None

        def elapsed_ms(start: float) -> int:
            return int((time.perf_counter() - start) * 1000)

        def update_quick_status(adapter_name: str, payload: dict[str, Any] | None, start: float, error: str | None = None) -> None:
            summary = self._summarize_tool_payload(adapter_name, payload, result.quick_scan)
            summary["stage"] = "quick"
            summary["duration_ms"] = elapsed_ms(start)
            if error:
                summary["status"] = "failed"
                summary["error"] = error
            result.tool_status[adapter_name] = summary

        def skip_quick_adapter(adapter_name: str, reason: str) -> None:
            payload = {"skipped": True, "reason": reason}
            result.tool_status[adapter_name] = {
                "status": "skipped",
                "stage": "quick",
                "duration_ms": 0,
                **payload,
            }
            self._record_action(trajectory, f"{adapter_name}.skipped", payload)
            self._emit_progress(
                progress_callback,
                "adapter_skipped",
                {"stage": "quick", "adapter": adapter_name, **payload},
            )

        sniff_start = time.perf_counter()
        try:
            self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "sniff"})
            sniff = sniff_binary(binary)
            result.quick_scan["sniff"] = sniff
            result.tool_status["sniff"] = {
                "status": "completed",
                "stage": "quick",
                "duration_ms": elapsed_ms(sniff_start),
            }
            self._record_action(trajectory, "sniff.quick", sniff)
            self._emit_progress(
                progress_callback,
                "adapter_completed",
                {"stage": "quick", "adapter": "sniff", "payload": sniff},
            )
        except Exception as exc:  # pragma: no cover - host tools missing
            result.notes.append(f"sniff failed: {exc}")
            result.tool_status["sniff"] = {
                "status": "failed",
                "stage": "quick",
                "duration_ms": elapsed_ms(sniff_start),
                "error": str(exc),
            }
            self._emit_progress(
                progress_callback,
                "adapter_failed",
                {"stage": "quick", "adapter": "sniff", "error": str(exc)},
            )

        if binary_format:
            start = time.perf_counter()
            try:
                self._emit_progress(
                    progress_callback,
                    "adapter_started",
                    {"stage": "quick", "adapter": "binary_format"},
                )
                metadata = binary_format.quick_scan(binary)
                result.quick_scan["binary_format"] = metadata
                update_quick_status("binary_format", metadata, start)
                self._record_action(trajectory, "binary_format.quick", metadata)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "binary_format", "payload": metadata},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                update_quick_status("binary_format", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "binary_format", "error": str(exc)},
                )

        subject_is_code = self._is_code_subject(binary, result)

        # AutoProfile shells out to file/strings/readelf/checksec/binwalk and
        # overlaps the format-specific path below. Keep it as an exhaustive
        # executable enrichment, not a tax on every intake.
        if autoprofile and subject_is_code and result.plan.profile == "exhaustive":
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "autoprofile"})
                profile = autoprofile.quick_scan(binary)
                result.quick_scan["autoprofile"] = profile
                update_quick_status("autoprofile", profile, start)
                self._record_action(trajectory, "autoprofile.quick", profile)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "autoprofile", "payload": profile},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                update_quick_status("autoprofile", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "autoprofile", "error": str(exc)},
                )
        elif autoprofile:
            skip_quick_adapter(
                "autoprofile",
                "only scheduled for exhaustive executable profiling; the default path uses format-specific evidence",
            )

        if firmware and not subject_is_code:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "firmware"})
                inventory = firmware.quick_scan(binary)
                result.quick_scan["firmware"] = inventory
                update_quick_status("firmware", inventory, start)
                self._record_action(trajectory, "firmware.quick", inventory)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "firmware", "payload": inventory},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                update_quick_status("firmware", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "firmware", "error": str(exc)},
                )
        elif firmware:
            skip_quick_adapter(
                "firmware",
                "top-level subject is executable; container inventory is not applicable",
            )

        if libmagic:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "libmagic"})
                info = libmagic.quick_scan(binary)
                result.quick_scan["libmagic"] = info
                result.quick_scan["identification"] = info
                update_quick_status("libmagic", info, start)
                self._record_action(trajectory, "libmagic.quick", info)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "libmagic", "payload": info},
                )
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                update_quick_status("libmagic", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "libmagic", "error": str(exc)},
                )

        if self._is_elf_subject(binary, result):
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "runtime"})
                runtime_info = get_runtime_requirements(binary)
                if "error" in runtime_info:
                    result.quick_scan["runtime"] = {"error": runtime_info["error"]}
                else:
                    result.quick_scan["runtime"] = runtime_info.get("runtime", {})
                    result.quick_scan["readelf"] = runtime_info.get("readelf", {})
                    result.quick_scan["packer"] = runtime_info.get("packer", {})
                result.tool_status["runtime"] = {
                    "status": "completed" if "error" not in runtime_info else "partial",
                    "stage": "quick",
                    "duration_ms": elapsed_ms(start),
                    "warnings": [str(runtime_info["error"])] if "error" in runtime_info else [],
                }
                self._record_action(trajectory, "runtime.quick", runtime_info)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "runtime", "payload": runtime_info},
                )
            except Exception as exc:  # pragma: no cover - best effort
                result.notes.append(f"runtime requirements failed: {exc}")
                result.tool_status["runtime"] = {
                    "status": "failed",
                    "stage": "quick",
                    "duration_ms": elapsed_ms(start),
                    "error": str(exc),
                }
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "runtime", "error": str(exc)},
                )
        else:
            runtime_info = {
                "skipped": True,
                "reason": "top-level subject is not ELF; firmware inventory should identify embedded analysis targets",
            }
            result.quick_scan["runtime"] = runtime_info
            result.tool_status["runtime"] = {"status": "skipped", "stage": "quick", "duration_ms": 0, **runtime_info}
            self._record_action(trajectory, "runtime.skipped", runtime_info)
            self._emit_progress(
                progress_callback,
                "adapter_skipped",
                {"stage": "quick", "adapter": "runtime", **runtime_info},
            )

        if radare and subject_is_code:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "radare2"})
                scan = radare.quick_scan(binary)
                result.quick_scan["radare2"] = scan
                result.resource_tree = self._init_resource_tree(binary, scan)
                update_quick_status("radare2", scan, start)
                self._record_action(trajectory, "radare2.quick", scan)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "radare2", "payload": scan},
                )
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                update_quick_status("radare2", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "radare2", "error": str(exc)},
                )
        elif radare:
            skip_quick_adapter(
                "radare2",
                "top-level subject is a container or raw blob; select a carved code artifact",
            )
        else:
            result.notes.append("radare2 adapter unavailable; quick scan limited")
            result.tool_status["radare2"] = {
                "status": "skipped",
                "stage": "quick",
                "duration_ms": 0,
                "reason": "unavailable",
            }
            self._emit_progress(
                progress_callback,
                "adapter_skipped",
                {"stage": "quick", "adapter": "radare2", "reason": "unavailable"},
            )

        if not self._config.analysis.enable_die:
            skip_quick_adapter("die", "disabled; set analysis.enable_die=true")
        elif not self._has_adapter("die"):
            skip_quick_adapter("die", "Detect It Easy CLI (diec) is not on PATH")
        else:
            start = time.perf_counter()
            self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "die"})
            try:
                payload = self._registry.get("die").quick_scan(binary)
                result.quick_scan["die"] = payload
                update_quick_status("die", payload, start)
                self._record_action(trajectory, "die.quick", payload)
                self._emit_progress(progress_callback, "adapter_completed",
                                    {"stage": "quick", "adapter": "die", "payload": payload})
            except Exception as exc:
                result.notes.append(f"die failed: {exc}")
                update_quick_status("die", None, start, error=str(exc))
                self._record_action(trajectory, "die.failed", {"error": str(exc)})
                self._emit_progress(progress_callback, "adapter_failed",
                                    {"stage": "quick", "adapter": "die", "error": str(exc)})
        if not result.plan.deep:
            skip_quick_adapter("capa", "requires deep analysis with analysis.enable_capa=true")

        self._build_artifact_dag(result, binary, trajectory, progress_callback)

        self._emit_progress(progress_callback, "stage_completed", {"stage": "quick"})

    def _run_deep(
        self,
        binary: Path,
        result: AnalysisResult,
        trajectory: AnalysisTrajectory | None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None,
        plan: AnalysisPlan | None = None,
    ) -> None:
        _LOGGER.info("Starting deep analysis: %s", binary)
        self._emit_progress(progress_callback, "stage_started", {"stage": "deep"})
        lock = threading.Lock()

        def update_tool_status(
            adapter_name: str,
            payload: dict[str, Any] | None,
            error: str | None = None,
            duration_ms: int | None = None,
        ) -> None:
            summary = self._summarize_tool_payload(adapter_name, payload, result.quick_scan)
            summary["stage"] = "deep"
            if duration_ms is not None:
                summary["duration_ms"] = duration_ms
            if error:
                summary["status"] = "failed"
                summary["error"] = error
            with lock:
                result.tool_status[adapter_name] = summary

        def run_adapter(
            adapter_name: str,
            adapter: AnalyzerAdapter,
            runner: Callable[[], dict[str, Any]],
            *,
            issue_on_fail: bool,
            note_on_fail: bool,
        ) -> None:
            start = time.perf_counter()
            try:
                self._emit_progress(
                    progress_callback, "adapter_started", {"stage": "deep", "adapter": adapter_name}
                )
                payload = runner()
                duration_ms = int((time.perf_counter() - start) * 1000)
                with lock:
                    result.deep_scan[adapter_name] = payload
                skipped = payload.get("status") == "skipped"
                self._record_action(trajectory, f"{adapter_name}.{'skipped' if skipped else 'deep'}", payload)
                self._emit_progress(
                    progress_callback, "adapter_skipped" if skipped else "adapter_completed",
                    {"stage": "deep", "adapter": adapter_name, "payload": payload,
                     **({"reason": payload.get("reason")} if skipped else {})}
                )
                update_tool_status(adapter_name, payload, duration_ms=duration_ms)
            except AdapterUnavailable as exc:
                duration_ms = int((time.perf_counter() - start) * 1000)
                if issue_on_fail:
                    result.issues.append(str(exc))
                if note_on_fail:
                    result.notes.append(str(exc))
                self._emit_progress(
                    progress_callback, "adapter_failed", {"stage": "deep", "adapter": adapter_name, "error": str(exc)}
                )
                update_tool_status(adapter_name, None, error=str(exc), duration_ms=duration_ms)
            except Exception as exc:
                # One crashed adapter must not abort the remaining deep stage.
                duration_ms = int((time.perf_counter() - start) * 1000)
                result.issues.append(f"{adapter_name} crashed: {type(exc).__name__}: {exc}")
                _LOGGER.exception("Deep adapter %s crashed", adapter_name)
                self._emit_progress(
                    progress_callback, "adapter_failed", {"stage": "deep", "adapter": adapter_name, "error": str(exc)}
                )
                update_tool_status(adapter_name, None, error=f"{type(exc).__name__}: {exc}", duration_ms=duration_ms)
        radare = self._registry.get("radare2") if self._has_adapter("radare2") else None
        ghidra = self._registry.get("ghidra") if self._has_adapter("ghidra") else None
        capstone = self._registry.get("capstone") if self._has_adapter("capstone") else None
        dwarf = self._registry.get("dwarf") if self._has_adapter("dwarf") else None
        # Only get angr adapter if run_angr is enabled in plan
        run_angr = plan.run_angr if plan else self._config.analysis.enable_angr
        angr = self._registry.get("angr") if self._has_adapter("angr") and run_angr else None
        frida = (
            self._registry.get("frida")
            if self._has_adapter("frida") and self._config.analysis.enable_frida
            else None
        )
        gef = self._registry.get("gef") if self._has_adapter("gef") and self._config.analysis.enable_gef else None
        subject_is_elf = self._is_elf_subject(binary, result)
        subject_is_code = self._is_code_subject(binary, result)
        non_code_reason = "top-level subject is not ELF, PE, or Mach-O; select an embedded code artifact"

        def skip_adapter(adapter_name: str, reason: str) -> None:
            payload = {"skipped": True, "reason": reason}
            with lock:
                result.tool_status[adapter_name] = {"status": "skipped", "stage": "deep", "duration_ms": 0, **payload}
            self._record_action(trajectory, f"{adapter_name}.skipped", payload)
            self._emit_progress(
                progress_callback,
                "adapter_skipped",
                {"stage": "deep", "adapter": adapter_name, **payload},
            )

        if not subject_is_code:
            self._run_firmware_child_fanout(
                result,
                trajectory,
                progress_callback,
                {
                    "radare2": radare,
                    "ghidra": ghidra,
                    "angr": angr,
                },
            )

        if radare and subject_is_code:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "deep", "adapter": "radare2"})
                deep = radare.deep_scan(binary)
                duration_ms = int((time.perf_counter() - start) * 1000)
                result.deep_scan["radare2"] = deep
                result.resource_tree = self._populate_tree_from_radare(
                    result.resource_tree, deep
                )
                self._record_action(trajectory, "radare2.deep", deep)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": "radare2", "payload": deep},
                )
                update_tool_status("radare2", deep, duration_ms=duration_ms)
            except AdapterUnavailable as exc:
                duration_ms = int((time.perf_counter() - start) * 1000)
                result.issues.append(str(exc))
                self._emit_progress(
                    progress_callback, "adapter_failed", {"stage": "deep", "adapter": "radare2", "error": str(exc)}
                )
                update_tool_status("radare2", None, error=str(exc), duration_ms=duration_ms)
            except Exception as exc:
                # Tree population or status bookkeeping must not kill the run.
                duration_ms = int((time.perf_counter() - start) * 1000)
                result.issues.append(f"radare2 crashed: {type(exc).__name__}: {exc}")
                _LOGGER.exception("radare2 deep stage crashed")
                self._emit_progress(
                    progress_callback, "adapter_failed", {"stage": "deep", "adapter": "radare2", "error": str(exc)}
                )
                update_tool_status("radare2", None, error=f"{type(exc).__name__}: {exc}", duration_ms=duration_ms)
        elif radare:
            skip_adapter("radare2", non_code_reason)

        tasks: list[tuple[str, AnalyzerAdapter, Callable[[], dict[str, Any]], bool, bool]] = []

        if not self._config.analysis.enable_capa:
            skip_adapter("capa", "disabled; set analysis.enable_capa=true")
        elif not subject_is_code:
            skip_adapter("capa", non_code_reason)
        elif not self._has_adapter("capa"):
            skip_adapter("capa", "Mandiant capa CLI is not on PATH")
        else:
            capa = self._registry.get("capa")
            tasks.append(("capa", capa, lambda: capa.deep_scan(binary), False, True))

        if ghidra and subject_is_code:
            tasks.append((
                "ghidra",
                ghidra,
                lambda: ghidra.deep_scan(binary, resource_tree=result.resource_tree),
                True,
                False,
            ))
        elif ghidra:
            skip_adapter("ghidra", non_code_reason)

        if capstone and result.resource_tree and subject_is_code:
            def _capstone_run() -> dict[str, Any]:
                quick = result.quick_scan.get("radare2", {})
                info = quick.get("info", {}) if isinstance(quick, dict) else {}
                bin_info = info.get("bin", {}) if isinstance(info.get("bin"), dict) else {}
                format_metadata = result.quick_scan.get("binary_format", {})
                normalized = format_metadata if isinstance(format_metadata, dict) else {}
                return capstone.quick_scan(
                    binary,
                    arch=normalized.get("arch") or bin_info.get("arch"),
                    bits=normalized.get("bits") or bin_info.get("bits"),
                    format_metadata=normalized,
                )

            tasks.append(("capstone", capstone, _capstone_run, False, True))
        elif capstone and not subject_is_code:
            skip_adapter("capstone", non_code_reason)

        if dwarf and subject_is_elf:
            tasks.append(("dwarf", dwarf, lambda: dwarf.deep_scan(binary), False, True))
        elif dwarf:
            skip_adapter("dwarf", "DWARF extraction requires an ELF subject")

        if angr and subject_is_code:
            tasks.append(("angr", angr, lambda: angr.deep_scan(binary), False, True))
        elif angr:
            skip_adapter("angr", non_code_reason)

        if frida and subject_is_code:
            tasks.append(("frida", frida, lambda: frida.deep_scan(binary), False, True))
        elif frida:
            skip_adapter("frida", non_code_reason)

        if gef and subject_is_elf:
            tasks.append(("gef", gef, lambda: gef.deep_scan(binary), False, True))
        elif gef:
            skip_adapter("gef", "GEF execution tracing currently requires an ELF subject")

        if tasks:
            with ThreadPoolExecutor(max_workers=min(len(tasks), self._config.performance.parallel_functions)) as executor:
                futures = {
                    executor.submit(run_adapter, name, adapter, runner, issue_on_fail=issue, note_on_fail=note): name
                    for name, adapter, runner, issue, note in tasks
                }
                for future in as_completed(futures):
                    future.result()

        self._emit_progress(progress_callback, "stage_completed", {"stage": "deep"})

        result.evidence_coverage = self._build_evidence_coverage(result)
        result.analysis_graph = build_analysis_graph(result)

    def _init_resource_tree(self, binary: Path, scan: dict[str, Any]) -> Resource:
        info = scan.get("info", {}) if isinstance(scan, dict) else {}
        bin_meta = info.get("bin", {}) if isinstance(info, dict) else {}
        architecture = bin_meta.get("arch") if isinstance(bin_meta, dict) else None

        return BinaryResource(
            kind="binary",
            name=binary.name,
            path=str(binary),
            architecture=architecture,
            metadata={"size": bin_meta.get("bintype"), "format": bin_meta.get("class")},
        )

    def _populate_tree_from_radare(
        self,
        resource_tree: Resource | None,
        deep_scan: dict[str, Any],
    ) -> Resource | None:
        if resource_tree is None:
            return None

        functions = deep_scan.get("functions") or []
        if isinstance(functions, list):
            for func in functions[:200]:
                if not isinstance(func, dict):
                    continue
                if any(child.metadata.get("offset") == func.get("offset") for child in resource_tree.children):
                    continue
                function_node = FunctionResource(
                    kind="function",
                    name=str(func.get("name", "func")),
                    metadata=func,
                    address=func.get("offset"),
                    size=func.get("size"),
                )
                resource_tree.add_child(function_node)

        return resource_tree

    def _build_artifact_dag(
        self,
        result: AnalysisResult,
        binary: Path,
        trajectory: AnalysisTrajectory | None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None,
    ) -> None:
        settings = self._config.extract
        firmware = result.quick_scan.get("firmware") if isinstance(result.quick_scan, dict) else None
        firmware_d = firmware if isinstance(firmware, dict) else {}
        if not firmware_d:
            format_metadata = result.quick_scan.get("binary_format", {})
            normalized_format = (
                str(format_metadata.get("format") or "").lower()
                if isinstance(format_metadata, dict)
                else ""
            )
            sniff = result.quick_scan.get("sniff", {})
            firmware_d = {
                "sha256": sniff.get("sha256") if isinstance(sniff, dict) else None,
                "is_elf": normalized_format == "elf",
                "top_level_format": normalized_format,
                "embedded_artifacts": [],
                "string_signals": {},
            }
        is_executable = bool(firmware_d.get("is_executable") or firmware_d.get("is_elf"))
        if str(firmware_d.get("top_level_format") or "").lower() in {
            "elf",
            "pe",
            "macho",
            "fat_macho",
        }:
            is_executable = True
        run_extractors = bool(settings.enable) and (settings.extract_elf or not is_executable)
        start = time.perf_counter()
        self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "artifact_dag"})
        try:
            dag = build_artifact_dag(
                binary,
                firmware=firmware_d or None,
                radare2=result.quick_scan.get("radare2") if isinstance(result.quick_scan, dict) else None,
                artifacts_dir=self._config.output.artifacts_dir,
                limits=ExtractLimits(
                    timeout_s=settings.timeout_s,
                    max_files=settings.max_files,
                    max_bytes=settings.max_bytes,
                    max_depth=settings.max_depth,
                    allow_unsafe_fallback=settings.allow_unsafe_fallback,
                ),
                run_extractors=run_extractors,
                extract_elf=settings.extract_elf,
            )
            compact = compact_dag(dag)
            result.quick_scan["artifact_dag"] = compact
            digest = str(dag.get("sha256") or "")
            if digest and self._config.output.save_artifacts:
                dump_dag(
                    self._config.output.artifacts_dir / "dags" / digest[:2] / digest / "dag.json",
                    dag,
                )
            self._record_action(trajectory, "artifact_dag.build", compact_dag(dag, max_nodes=24))
            self._emit_progress(
                progress_callback,
                "adapter_completed",
                {"stage": "quick", "adapter": "artifact_dag", "payload": dag.get("summary")},
            )
            elapsed = round((time.perf_counter() - start) * 1000)
            result.tool_status["artifact_dag"] = {
                "status": "completed",
                "elapsed_ms": elapsed,
                "available": True,
            }
            result.tool_availability["artifact_dag"] = True
        except Exception as exc:
            _LOGGER.debug("artifact DAG failed: %s", exc)
            result.notes.append(f"artifact DAG skipped: {exc}")
            result.tool_status["artifact_dag"] = {"status": "failed", "error": str(exc), "available": False}
            self._emit_progress(
                progress_callback,
                "adapter_failed",
                {"stage": "quick", "adapter": "artifact_dag", "error": str(exc)},
            )

    def _run_firmware_child_fanout(
        self,
        result: AnalysisResult,
        trajectory: AnalysisTrajectory | None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None,
        adapters: dict[str, AnalyzerAdapter | None],
    ) -> None:
        firmware = result.quick_scan.get("firmware") if isinstance(result.quick_scan, dict) else None
        if not isinstance(firmware, dict):
            return

        fanout_tasks = firmware.get("fanout_tasks")
        carved_targets = firmware.get("carved_targets")
        if not isinstance(fanout_tasks, list) or not isinstance(carved_targets, list):
            return

        code_targets: list[dict[str, Any]] = []
        for target in carved_targets:
            if not isinstance(target, dict):
                continue
            if target.get("analysis_role") == "code" and target.get("carved_path"):
                code_targets.append(target)
        code_targets = code_targets[:4]

        fanout_result: dict[str, Any] = {
            "mode": "firmware_child_fanout",
            "targets": code_targets,
            "tasks": fanout_tasks,
            "analyses": [],
            "skipped": [],
        }

        if not code_targets:
            fanout_result["skipped"].append({
                "reason": "No carved ELF/code targets were found in the firmware inventory.",
            })
            result.deep_scan["firmware_children"] = fanout_result
            self._record_action(trajectory, "firmware_children.skipped", fanout_result)
            return

        adapter_plan = {
            name: adapter
            for name, adapter in adapters.items()
            if adapter is not None and name in {"radare2", "ghidra", "angr"}
        }
        if not adapter_plan:
            fanout_result["skipped"].append({
                "reason": "No code analyzers are available for carved firmware children.",
                "wanted": ["radare2", "ghidra", "angr"],
            })
            result.deep_scan["firmware_children"] = fanout_result
            self._record_action(trajectory, "firmware_children.skipped", fanout_result)
            return

        def run_child_tool(target: dict[str, Any], name: str, adapter: AnalyzerAdapter) -> dict[str, Any]:
            target_path = Path(str(target["carved_path"]))
            payload: dict[str, Any] = {
                "target": str(target_path),
                "offset": target.get("offset"),
                "kind": target.get("kind"),
                "tool": name,
                "status": "completed",
            }
            try:
                self._emit_progress(
                    progress_callback,
                    "adapter_started",
                    {"stage": "deep", "adapter": f"firmware_child.{name}", "binary": str(target_path)},
                )
                if name == "radare2":
                    quick = adapter.quick_scan(target_path)
                    deep = adapter.deep_scan(target_path)
                    payload["quick"] = quick
                    payload["deep"] = deep
                else:
                    payload["deep"] = adapter.deep_scan(target_path)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": f"firmware_child.{name}", "payload": payload},
                )
            except Exception as exc:
                payload["status"] = "failed"
                payload["error"] = str(exc)
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": f"firmware_child.{name}", "error": str(exc)},
                )
            return payload

        jobs: list[tuple[dict[str, Any], str, AnalyzerAdapter]] = []
        for target in code_targets:
            raw_requested_tools = target.get("fanout_tools")
            requested_tools: list[Any] = raw_requested_tools if isinstance(raw_requested_tools, list) else []
            for name, adapter in adapter_plan.items():
                if name in requested_tools:
                    jobs.append((target, name, adapter))

        if not jobs:
            fanout_result["skipped"].append({
                "reason": "Carved code targets did not request any currently available analyzer.",
                "available": sorted(adapter_plan),
            })
        else:
            with ThreadPoolExecutor(max_workers=min(len(jobs), self._config.performance.parallel_functions)) as executor:
                futures = [executor.submit(run_child_tool, target, name, adapter) for target, name, adapter in jobs]
                for future in as_completed(futures):
                    fanout_result["analyses"].append(future.result())

        result.deep_scan["firmware_children"] = fanout_result
        self._record_action(trajectory, "firmware_children.fanout", fanout_result)

    def _has_adapter(self, name: str) -> bool:
        try:
            self._registry.get(name)
        except AdapterUnavailable:
            return False
        return True

    def _record_action(
        self,
        trajectory: AnalysisTrajectory | None,
        action: str,
        payload: Any,
    ) -> None:
        if not trajectory or not self._trajectory_dao:
            return
        action_entry = TrajectoryAction(action=action, payload=payload)
        self._trajectory_dao.append_action(trajectory, action_entry)

    def _summarize_tool_payload(
        self,
        adapter_name: str,
        payload: dict[str, Any] | None,
        quick_scan: dict[str, Any],
    ) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "status": "completed" if payload else "failed",
            "functions_count": 0,
            "cfg_nodes": 0,
            "cfg_edges": 0,
            "memory_allocations": [],
            "warnings": [],
        }
        if not payload:
            return summary

        if adapter_name in {"die", "capa"}:
            summary["status"] = payload.get("status", "completed")
            summary["warnings"] = payload.get("warnings", [])
            if payload.get("reason"):
                summary["reason"] = payload["reason"]
            for key in ("detection_count", "capability_count", "evidence_kind"):
                if key in payload:
                    summary[key] = payload[key]
            return summary

        def extract_symbol_names(entries: list[dict[str, Any]]) -> list[str]:
            names: list[str] = []
            for entry in entries:
                name = entry.get("name")
                if isinstance(name, str):
                    names.append(name)
            return names

        alloc_symbols = {
            "malloc",
            "calloc",
            "realloc",
            "free",
            "new",
            "delete",
            "operator_new",
            "operator_delete",
            "mmap",
            "brk",
        }

        functions = payload.get("functions", [])
        if isinstance(functions, list):
            summary["functions_count"] = len(functions)

        if adapter_name == "radare2":
            function_cfgs = payload.get("function_cfgs", [])
            if isinstance(function_cfgs, list):
                block_count = 0
                edge_count = 0
                for fn in function_cfgs:
                    blocks = fn.get("blocks", []) if isinstance(fn, dict) else []
                    if isinstance(blocks, list):
                        block_count += len(blocks)
                        for block in blocks:
                            if not isinstance(block, dict):
                                continue
                            if block.get("jump"):
                                edge_count += 1
                            if block.get("fail"):
                                edge_count += 1
                summary["cfg_nodes"] = block_count
                summary["cfg_edges"] = edge_count
            imports = quick_scan.get("radare2", {}).get("imports", [])
            symbols = payload.get("symbols", [])
            sections = payload.get("sections", [])
            summary["symbol_count"] = len(symbols) if isinstance(symbols, list) else 0
            summary["import_count"] = len(imports) if isinstance(imports, list) else 0
            summary["section_count"] = len(sections) if isinstance(sections, list) else 0
            if isinstance(imports, list):
                names = extract_symbol_names(imports)
                summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})

        if adapter_name == "angr":
            cfg = payload.get("cfg", {})
            if isinstance(cfg, dict):
                summary["cfg_nodes"] = int(cfg.get("node_count") or cfg.get("nodes") or 0)
                summary["cfg_edges"] = int(cfg.get("edge_count") or cfg.get("edges") or 0)
            names = extract_symbol_names(functions) if isinstance(functions, list) else []
            summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})
        if adapter_name == "ghidra":
            names = extract_symbol_names(functions) if isinstance(functions, list) else []
            summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})


        if adapter_name == "firmware":
            summary["status"] = "completed"
            artifacts = payload.get("embedded_artifacts")
            targets = payload.get("recommended_targets")
            summary["artifact_count"] = len(artifacts) if isinstance(artifacts, list) else 0
            summary["recommended_target_count"] = len(targets) if isinstance(targets, list) else 0
            summary["top_level_format"] = payload.get("top_level_format")
            summary["container_type"] = payload.get("container_type")

        if adapter_name == "capstone":
            summary["warnings"].append("Instruction-only output (no functions/CFG).")
            summary["status"] = "partial"

        has_r2_inventory = adapter_name == "radare2" and any(
            int(summary.get(key) or 0) > 0
            for key in ("symbol_count", "import_count", "section_count")
        )
        if (
            summary["functions_count"] == 0
            and summary["cfg_nodes"] == 0
            and adapter_name in {"radare2", "angr", "ghidra"}
            and not has_r2_inventory
        ):
            summary["status"] = "partial"
            summary["warnings"].append("No functions/CFG extracted.")

        return summary

    def _build_evidence_coverage(self, result: AnalysisResult) -> dict[str, Any]:
        columns = ["functions", "cfg", "strings", "imports", "runtime", "allocs", "packer"]
        rows = ["sniff", "firmware", "radare2", "ghidra", "angr", "capstone", "dwarf", "readelf", "packer"]

        r2_quick = result.quick_scan.get("radare2", {}) if isinstance(result.quick_scan, dict) else {}
        r2_strings = r2_quick.get("strings", []) if isinstance(r2_quick, dict) else []
        r2_imports = r2_quick.get("imports", []) if isinstance(r2_quick, dict) else []

        runtime = result.quick_scan.get("runtime", {})
        packer = result.quick_scan.get("packer", {})

        def status_cell(value: bool | None) -> str:
            if value is None:
                return "missing"
            return "present" if value else "missing"

        matrix: dict[str, dict[str, str]] = {row: {col: "missing" for col in columns} for row in rows}

        firmware = result.quick_scan.get("firmware", {}) if isinstance(result.quick_scan, dict) else {}
        if isinstance(firmware, dict):
            matrix["firmware"]["strings"] = "partial" if firmware.get("embedded_artifacts") else "missing"
            matrix["firmware"]["runtime"] = "partial" if firmware.get("recommended_targets") else "missing"

        tool_status = result.tool_status or {}
        for tool in ("radare2", "ghidra", "angr", "capstone", "dwarf"):
            summary = tool_status.get(tool, {})
            functions = (summary.get("functions_count") or 0) > 0
            cfg = (summary.get("cfg_nodes") or 0) > 0
            allocs = bool(summary.get("memory_allocations"))
            matrix[tool]["functions"] = status_cell(functions)
            matrix[tool]["cfg"] = "present" if cfg else ("partial" if summary.get("status") == "partial" else "missing")
            matrix[tool]["allocs"] = status_cell(allocs)

        matrix["radare2"]["strings"] = status_cell(len(r2_strings) > 0)
        matrix["radare2"]["imports"] = status_cell(len(r2_imports) > 0)

        sniff = result.quick_scan.get("sniff", {}) if isinstance(result.quick_scan, dict) else {}
        sniff_strings = sniff.get("strings", []) if isinstance(sniff, dict) else []
        if "sniff" not in matrix:
            matrix["sniff"] = {col: "missing" for col in columns}
        if isinstance(sniff, dict) and sniff.get("file"):
            matrix["sniff"]["runtime"] = "present"
        matrix["sniff"]["strings"] = status_cell(isinstance(sniff_strings, list) and len(sniff_strings) > 0)
        matrix["sniff"]["imports"] = "partial" if isinstance(sniff, dict) and sniff.get("readelf") else "missing"

        matrix["readelf"]["runtime"] = status_cell(bool(runtime) and "error" not in runtime)
        matrix["readelf"]["imports"] = status_cell(bool(runtime) and bool(runtime.get("needed")))
        matrix["readelf"]["strings"] = "missing"

        matrix["packer"]["packer"] = status_cell(bool(packer) and bool(packer.get("detected")))
        if packer and packer.get("detected") is False:
            matrix["packer"]["packer"] = "partial"

        return {
            "columns": columns,
            "rows": rows,
            "matrix": matrix,
        }

    def _emit_progress(
        self,
        callback: Callable[[str, dict[str, Any]], None] | None,
        event: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        if not callback:
            return
        try:
            callback(event, payload or {})
        except Exception:  # pragma: no cover - defensive hook
            _LOGGER.exception("Progress callback failed for event %s", event)

    def _ensure_elf(self, binary: Path) -> None:
        try:
            with binary.open("rb") as handle:
                magic = handle.read(4)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"Binary not found: {binary}") from exc
        except OSError as exc:  # pragma: no cover - unexpected IO error
            raise RuntimeError(f"Unable to read binary {binary}: {exc}") from exc

        if magic != b"\x7fELF":
            raise ValueError(
                f"{binary} is not an ELF binary (expected 0x7f454c46 header, got {magic!r})"
            )

    def _is_elf_subject(self, binary: Path, result: AnalysisResult | None = None) -> bool:
        firmware = (result.quick_scan.get("firmware") if result and isinstance(result.quick_scan, dict) else None)
        if isinstance(firmware, dict) and isinstance(firmware.get("is_elf"), bool):
            return bool(firmware["is_elf"])
        try:
            with binary.open("rb") as handle:
                return handle.read(4) == b"\x7fELF"
        except OSError:
            return False

    def _is_code_subject(self, binary: Path, result: AnalysisResult | None = None) -> bool:
        metadata = (
            result.quick_scan.get("binary_format")
            if result and isinstance(result.quick_scan, dict)
            else None
        )
        if isinstance(metadata, dict):
            return str(metadata.get("format") or "").lower() in {
                "elf",
                "pe",
                "macho",
                "fat_macho",
            }
        try:
            with binary.open("rb") as handle:
                magic = handle.read(4)
        except OSError:
            return False
        return magic == b"\x7fELF" or magic[:2] == b"MZ" or magic in {
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        }
