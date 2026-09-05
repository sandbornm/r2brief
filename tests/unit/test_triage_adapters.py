import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from r2b.adapters.base import AdapterRegistry, AdapterUnavailable
from r2b.adapters.triage import CapaAdapter, DetectItEasyAdapter, _run_json
from r2b.analysis.briefing import build_briefing, render_briefing_markdown
from r2b.analysis.orchestrator import AnalysisOrchestrator, AnalysisPlan, AnalysisResult
from r2b.analysis.provenance import build_analysis_provenance
from r2b.config import AppConfig
from r2b.environment.detectors import EnvironmentReport
from r2b.extract.unblob import UnblobExtractor, _parse_report


def cli_result(monkeypatch, code, report, diagnostic=""):
    monkeypatch.setattr("r2b.adapters.triage.shutil.which", lambda name: f"/tools/{name}")
    runner = Mock(return_value=(code, report, diagnostic))
    monkeypatch.setattr("r2b.adapters.triage._run_json", runner)
    return runner


def test_die_retains_native_evidence_and_literal_filename(monkeypatch, tmp_path):
    native = {"detects": [{"filetype": "ELF64", "values": [
        {"type": "Compiler", "name": "GCC", "version": "12", "info": "heuristic"}
    ]}]}
    runner = cli_result(monkeypatch, 0, native)
    binary = tmp_path / "-file with spaces;$.elf"
    result = DetectItEasyAdapter().quick_scan(binary)
    assert result["detections"][0]["name"] == "GCC"
    assert result["report"] == native
    assert runner.call_args.args[0] == ["/tools/diec", "--json", str(binary)]


def test_capa_preserves_match_tree_and_address_type(monkeypatch, tmp_path):
    address = {"type": "absolute", "value": 4096}
    native = {"meta": {"version": "test"}, "rules": {
        "read/file~test": {"meta": {"namespace": "host-interaction/file-system"},
                           "matches": [[address, {"success": True, "children": []}]]},
        "internal": {"meta": {"lib": True}, "matches": []},
    }}
    cli_result(monkeypatch, 0, native)
    result = CapaAdapter().deep_scan(tmp_path / "sample.exe")
    assert result["capability_count"] == 1
    assert result["capabilities"][0]["locations"] == [address]
    assert result["capabilities"][0]["report_ref"] == "/rules/read~1file~0test"
    assert result["report"] == native


@pytest.mark.parametrize("code", [16, 17, 18])
def test_capa_unsupported_is_skipped(monkeypatch, tmp_path, code):
    cli_result(monkeypatch, code, {}, "unsupported input")
    result = CapaAdapter().deep_scan(tmp_path / "arm.elf")
    assert result["status"] == "skipped"
    assert "capabilities" not in result


def test_capa_limitations_and_empty_matches(monkeypatch, tmp_path):
    cli_result(monkeypatch, 14, {"meta": {}, "rules": {}}, "packed")
    assert CapaAdapter().deep_scan(tmp_path / "sample.exe")["status"] == "partial"
    cli_result(monkeypatch, 0, {"meta": {}, "rules": {}})
    result = CapaAdapter().deep_scan(tmp_path / "sample.exe")
    assert result["status"] == "completed"
    assert result["capability_count"] == 0


def test_capa_missing_rules_fails(monkeypatch, tmp_path):
    cli_result(monkeypatch, 10, {}, "rules missing")
    with pytest.raises(AdapterUnavailable, match="rules missing"):
        CapaAdapter().deep_scan(tmp_path / "sample.exe")


@pytest.mark.parametrize("adapter", [DetectItEasyAdapter(), CapaAdapter()])
def test_missing_cli(monkeypatch, tmp_path, adapter):
    monkeypatch.setattr("r2b.adapters.triage.shutil.which", lambda name: None)
    assert not adapter.is_available()
    with pytest.raises(AdapterUnavailable, match="not on PATH"):
        adapter.deep_scan(tmp_path / "sample")


def test_json_runner_rejects_invalid_and_large_output(monkeypatch):
    output = b"not json"

    def run(argv, **kwargs):
        kwargs["stdout"].write(output)
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 3
        assert "shell" not in kwargs
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("r2b.adapters.triage.subprocess.run", run)
    with pytest.raises(AdapterUnavailable, match="invalid JSON"):
        _run_json(["diec"], 3)
    monkeypatch.setattr("r2b.adapters.triage.MAX_REPORT_BYTES", 2)
    output = b'{"detects": []}'
    with pytest.raises(AdapterUnavailable, match="report limit"):
        _run_json(["diec"], 3)


def test_timeout_is_adapter_failure(monkeypatch):
    monkeypatch.setattr("r2b.adapters.triage.subprocess.run",
                        Mock(side_effect=subprocess.TimeoutExpired("capa", 1)))
    with pytest.raises(AdapterUnavailable):
        _run_json(["capa"], 1)


def test_supplemental_evidence_does_not_rerank_and_has_provenance(tmp_path):
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")
    result = AnalysisResult(binary, AnalysisPlan())
    original = build_briefing(result)
    result.deep_scan["capa"] = {"status": "completed", "capability_count": 1,
        "capabilities": [{"name": "read file", "namespace": "host/file"}],
        "report": {"meta": {}, "rules": {}}}
    result.provenance = build_analysis_provenance(result, AppConfig())
    updated = build_briefing(result)
    assert updated["regions"] == original["regions"]
    assert updated["handoff"] == original["handoff"]
    assert updated["triage_tools"]["capa"]["total"] == 1
    assert "read file" in render_briefing_markdown(updated)
    assert any(a.get("result_ref") == "/deep_scan/capa" for a in result.provenance["actions"])


def test_orchestrator_capa_gate_and_container_skip(monkeypatch, tmp_path):
    config = AppConfig()
    env = EnvironmentReport(python_version="3.11", uv_available=True, openai_key_present=False)
    orch = AnalysisOrchestrator(config, env)
    capa = Mock(name="capa")
    capa.name = "capa"
    capa.is_available.return_value = True
    capa.deep_scan.return_value = {"status": "completed", "capabilities": []}
    orch._registry = AdapterRegistry([capa])
    monkeypatch.setattr(orch, "_is_code_subject", lambda *args: True)
    monkeypatch.setattr(orch, "_is_elf_subject", lambda *args: False)
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")
    result = AnalysisResult(binary, AnalysisPlan())
    orch._run_deep(binary, result, None, None)
    assert result.tool_status["capa"]["status"] == "skipped"
    capa.deep_scan.assert_not_called()
    config.analysis.enable_capa = True
    orch._run_deep(binary, result, None, None)
    assert result.tool_status["capa"]["status"] == "completed"
    capa.deep_scan.assert_called_once_with(binary)
    monkeypatch.setattr(orch, "_is_code_subject", lambda *args: False)
    orch._run_deep(binary, result, None, None)
    assert result.tool_status["capa"]["status"] == "skipped"
    assert capa.deep_scan.call_count == 1


def test_unblob_reads_only_root_chunk_offsets(tmp_path):
    subject = tmp_path / "firmware"
    report = tmp_path / "report.json"
    report.write_text(json.dumps([
        {"task": {"path": str(subject)}, "reports": [
            {"__typename__": "ChunkReport", "handler_name": "gzip",
             "start_offset": 32, "end_offset": 96, "size": 64},
            {"__typename__": "HashReport", "sha256": "irrelevant"}]},
        {"task": {"path": "/extracted/child"}, "reports": [
            {"__typename__": "ChunkReport", "handler_name": "zip", "start_offset": 999}]}
    ]))
    hits = _parse_report(report, subject=subject)
    assert len(hits) == 1
    assert (hits[0]["name"], hits[0]["offset"], hits[0]["size"]) == ("gzip", 32, 64)


def test_unblob_requests_report_and_keeps_extracted_files(monkeypatch, tmp_path):
    subject = tmp_path / "firmware"
    subject.write_bytes(b"firmware")

    def sandbox(argv, **kwargs):
        assert argv[argv.index("--process-num") + 1] == "1"
        report_path = Path(argv[argv.index("--report") + 1])
        report_path.write_text(json.dumps([{"task": {"path": str(subject)}, "reports": []}]))
        (kwargs["output_dir"] / "unblob" / "child.elf").write_bytes(b"\x7fELF")
        return Mock(returncode=0)

    monkeypatch.setattr("r2b.extract.unblob.run_sandboxed", sandbox)
    _, hits = UnblobExtractor("/usr/bin/unblob").extract(subject, tmp_path / "out")
    assert len(hits) == 1
    assert hits[0]["name"] == "child.elf"


@pytest.mark.parametrize("enabled,available,expected", [
    (False, True, "skipped"), (True, False, "skipped"), (True, True, "completed")])
def test_die_quick_gate_and_capa_not_run_in_quick(monkeypatch, tmp_path, enabled, available, expected):
    config = AppConfig()
    config.analysis.enable_die = enabled
    config.analysis.enable_capa = True
    env = EnvironmentReport(python_version="3.11", uv_available=True, openai_key_present=False)
    orch = AnalysisOrchestrator(config, env)
    die = Mock()
    die.name = "die"
    die.is_available.return_value = available
    die.quick_scan.return_value = {"status": "completed", "detections": []}
    orch._registry = AdapterRegistry([die])
    monkeypatch.setattr("r2b.analysis.orchestrator.sniff_binary", lambda _: {})
    monkeypatch.setattr(orch, "_build_artifact_dag", lambda *args: None)
    monkeypatch.setattr(orch, "_is_code_subject", lambda *args: False)
    monkeypatch.setattr(orch, "_is_elf_subject", lambda *args: False)
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")
    result = AnalysisResult(binary, AnalysisPlan(deep=False))
    orch._run_quick(binary, result, None, None)
    assert result.tool_status["die"]["status"] == expected
    assert result.tool_status["capa"]["status"] == "skipped"
    assert die.quick_scan.call_count == int(enabled and available)
