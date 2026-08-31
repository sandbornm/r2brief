from __future__ import annotations
import hashlib
from pathlib import Path

from r2b.analysis.briefing import build_briefing
from r2b.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2b.analysis.provenance import (
    PROVENANCE_SCHEMA_VERSION,
    build_analysis_provenance,
    render_replay_python,
    render_replay_shell,
)
from r2b.analysis.result_dto import analysis_result_to_public_dict
from r2b.config import AppConfig


def _result(binary: Path) -> AnalysisResult:
    return AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(
            quick=True,
            deep=True,
            run_angr=False,
            persist_trajectory=False,
            profile="standard",
        ),
        quick_scan={
            "sniff": {"file": "ELF 64-bit", "strings": ["hello"]},
            "radare2": {
                "info": {"bin": {"arch": "x86", "bits": 64, "os": "linux"}},
                "imports": [{"name": "strcpy"}],
            },
        },
        deep_scan={
            "radare2": {
                "function_count": 1,
                "entry_function": {"name": "main", "offset": 0x1000},
                "entry_disassembly": "0x1000 call sym.imp.strcpy",
            }
        },
        tool_availability={"sniff": True, "radare2": True, "ghidra": False},
        tool_status={
            "sniff": {"status": "completed", "stage": "quick", "duration_ms": 2},
            "radare2": {"status": "completed", "stage": "deep", "duration_ms": 8},
            "ghidra": {"status": "skipped", "stage": "deep", "reason": "unavailable"},
        },
    )


def test_provenance_is_ordered_portable_and_secret_free(tmp_path: Path) -> None:
    binary = tmp_path / "tiny fixture"
    binary.write_bytes(b"\x7fELF" + b"evidence")
    result = _result(binary)
    config = AppConfig()
    config.analysis.enable_ghidra = True
    config.extract.enable = True
    config.llm.api_key_env = "DO_NOT_EXPORT_ME"

    first = build_analysis_provenance(result, config)
    second = build_analysis_provenance(result, config)

    assert first == second
    assert first["schema_version"] == PROVENANCE_SCHEMA_VERSION
    assert first["input"]["sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert first["input"]["size_bytes"] == len(binary.read_bytes())
    assert first["plan"]["profile"] == "standard"
    assert "llm" not in first["config"]
    assert "DO_NOT_EXPORT_ME" not in repr(first)

    actions = first["actions"]
    assert [item["sequence"] for item in actions] == list(range(1, len(actions) + 1))
    assert [item["action"] for item in actions[:3]] == [
        "sniff.quick",
        "radare2.quick",
        "radare2.deep",
    ]
    assert actions[1]["status"] == "completed"  # deep status does not leak into quick
    assert actions[2]["result_ref"] == "/deep_scan/radare2"
    assert len(actions[2]["output_sha256"]) == 64
    assert actions[-1]["adapter"] == "ghidra"
    assert actions[-1]["status"] == "skipped"
    assert actions[-1]["result_ref"] is None

    assert first["replay"]["argv"] == [
        "r2b",
        "brief",
        "{input}",
        "--deep",
        "--extract",
        "--no-save",
        "--json",
    ]
    assert first["replay"]["shell"] == 'r2b brief "$R2B_INPUT" --deep --extract --no-save --json'


def test_replay_renderers_substitute_input_and_rebuild_config(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    provenance = build_analysis_provenance(_result(binary), AppConfig())

    assert render_replay_shell(provenance, input_path="/tmp/a b") == (
        "r2b brief '/tmp/a b' --deep --no-save --json"
    )
    recipe = render_replay_python(provenance, input_path="/tmp/a b")
    assert "AppConfig.model_validate" in recipe
    assert "AnalysisOptions(" in recipe
    assert "profile='standard'" in recipe
    assert provenance["input"]["sha256"] in recipe
    compile(recipe, "<r2b-replay>", "exec")


def test_public_payload_and_regions_link_to_producing_action(tmp_path: Path) -> None:
    binary = tmp_path / "sample.elf"
    binary.write_bytes(b"\x7fELF" + b"x" * 32)
    result = _result(binary)
    result.provenance = build_analysis_provenance(result, AppConfig())

    briefing = build_briefing(result)
    public = analysis_result_to_public_dict(result, briefing=briefing)

    assert public["provenance"] == result.provenance
    assert briefing["provenance"]["schema_version"] == PROVENANCE_SCHEMA_VERSION
    radare_regions = [
        region
        for region in briefing["regions"]
        if region.get("snippet", {}).get("source") == "radare2"
    ]
    assert radare_regions
    refs = radare_regions[0]["evidence_refs"]
    assert {ref["result_ref"] for ref in refs} == {
        "/quick_scan/radare2",
        "/deep_scan/radare2",
    }
