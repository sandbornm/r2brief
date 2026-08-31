from pathlib import Path

import pytest

from r2b.analysis.orchestrator import AnalysisOrchestrator, AnalysisPlan, AnalysisResult
from r2b.config import AppConfig
from r2b.environment.detectors import EnvironmentReport, ToolCheck


def build_env_report(tmp_path: Path) -> EnvironmentReport:
    return EnvironmentReport(
        python_version='3.11',
        uv_available=True,
        openai_key_present=False,
        tools=[
            ToolCheck(name='radare2', command='radare2', available=False),
        ],
        ghidra=None,
    )


def test_quick_scan_includes_host_sniff(tmp_path: Path):
    config = AppConfig()
    config.analysis.enable_angr = False
    config.analysis.enable_ghidra = False
    config.analysis.require_elf = False
    config.analysis.enable_trajectory_recording = False
    config.extract.enable = False
    config.output.artifacts_dir = tmp_path / "artifacts"
    env = build_env_report(tmp_path)
    orchestrator = AnalysisOrchestrator(config, env, trajectory_dao=None)

    blob = tmp_path / 'sample.bin'
    blob.write_bytes(b'fw-type:Cloud\x00httpd\x00login\n' + b'\x00' * 32)

    result = orchestrator.analyze(blob, AnalysisPlan(deep=False, persist_trajectory=False))
    assert 'sniff' in result.quick_scan
    assert result.quick_scan['sniff']['file']
    assert result.quick_scan['sniff']['hex_head']
    assert result.tool_status.get('sniff', {}).get('status') == 'completed'
    assert result.provenance['schema_version'] == 'r2b.provenance.v1'
    assert result.provenance['input']['sha256']
    assert result.provenance['actions'][0]['action'] == 'sniff.quick'


def test_ensure_elf_validation(tmp_path: Path):
    config = AppConfig()
    config.analysis.enable_angr = False
    config.analysis.enable_ghidra = False
    config.analysis.require_elf = True

    env = build_env_report(tmp_path)

    orchestrator = AnalysisOrchestrator(config, env, trajectory_dao=None)

    non_elf = tmp_path / 'not_elf.bin'
    non_elf.write_bytes(b'\x00\x00\x00\x00')

    with pytest.raises(ValueError):
        orchestrator._ensure_elf(non_elf)

    elf = tmp_path / 'sample.elf'
    elf.write_bytes(b'\x7fELF' + b'\x00' * 8)
    orchestrator._ensure_elf(elf)  # should not raise


def test_radare2_quick_inventory_is_not_reported_as_failed_depth(tmp_path: Path):
    orchestrator = AnalysisOrchestrator(AppConfig(), build_env_report(tmp_path), trajectory_dao=None)
    payload = {
        "symbols": [{"name": "main"}],
        "imports": [{"name": "strcpy"}],
        "sections": [{"name": ".text"}],
        "entry_function": {"name": "main", "offset": 0x1000},
    }

    status = orchestrator._summarize_tool_payload("radare2", payload, {"radare2": payload})

    assert status["status"] == "completed"
    assert status["symbol_count"] == 1
    assert status["import_count"] == 1
    assert status["section_count"] == 1
    assert status["warnings"] == []


class _FakeChildAnalyzer:
    name = "angr"

    def is_available(self) -> bool:
        return True

    def quick_scan(self, binary: Path, **kwargs):
        return {"entry": "0x1000"}

    def deep_scan(self, binary: Path, **kwargs):
        return {"functions": [{"addr": "0x1000", "name": "entry"}], "cfg": {"nodes": [], "edges": []}}


def test_firmware_child_fanout_runs_available_code_analyzers(tmp_path: Path):
    config = AppConfig()
    config.analysis.enable_angr = False
    config.analysis.enable_ghidra = False
    env = build_env_report(tmp_path)
    orchestrator = AnalysisOrchestrator(config, env, trajectory_dao=None)

    child = tmp_path / "child.elf"
    child.write_bytes(b"\x7fELF" + b"\x00" * 32)
    result = AnalysisResult(
        binary=tmp_path / "firmware.bin",
        plan=AnalysisPlan(),
        quick_scan={
            "firmware": {
                "carved_targets": [
                    {
                        "offset": 4096,
                        "kind": "elf_binary",
                        "analysis_role": "code",
                        "fanout_tools": ["angr"],
                        "carved_path": str(child),
                    }
                ],
                "fanout_tasks": [
                    {
                        "target": str(child),
                        "offset": 4096,
                        "kind": "elf_binary",
                        "role": "code",
                        "tools": ["angr"],
                        "status": "ready",
                    }
                ],
            }
        },
    )

    orchestrator._run_firmware_child_fanout(result, None, None, {"angr": _FakeChildAnalyzer()})

    children = result.deep_scan["firmware_children"]
    assert children["mode"] == "firmware_child_fanout"
    assert children["analyses"][0]["tool"] == "angr"
    assert children["analyses"][0]["status"] == "completed"
