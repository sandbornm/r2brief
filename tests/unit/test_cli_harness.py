"""CLI harness contract: --json on stdout, --ask optional, empty ask → exit 2."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from r2b.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2b.cli import app
from r2b.config import AppConfig
from r2b.state import AppState

runner = CliRunner()


def _json_payload(text: str) -> dict:
    start = text.find("{")
    assert start >= 0, text[:400]
    return json.loads(text[start:])


def _state(tmp_path: Path, result: AnalysisResult) -> AppState:
    orch = MagicMock()
    orch.create_plan.return_value = result.plan
    orch.analyze.return_value = result
    cfg = AppConfig()
    cfg.output.artifacts_dir = tmp_path / "art"
    cfg.extract.enable = False
    return AppState(
        config=cfg,
        env=MagicMock(),
        dao=None,
        chat_dao=None,
        orchestrator=orch,
        db=None,
    )


def _ls_result(binary: Path) -> AnalysisResult:
    return AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(quick=True, deep=False, persist_trajectory=False, profile="triage"),
        quick_scan={
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 64, "os": "linux"}, "core": {"format": "elf"}},
                "imports": [{"name": "strcpy"}, {"name": "ioctl"}],
            }
        },
    )


def test_env_json_exposes_llm_slot() -> None:
    result = runner.invoke(app, ["env", "--json"])
    assert result.exit_code == 0, result.output
    data = _json_payload(result.stdout)
    assert "openai_key_present" in data
    assert data["llm"]["provider"]
    assert "model" in data["llm"]
    assert "api_key_present" in data["llm"]


def test_setup_json_is_setup_v1() -> None:
    result = runner.invoke(app, ["setup", "--json"])
    assert result.exit_code == 0, result.output
    data = _json_payload(result.stdout)
    assert data["schema_version"] == "r2b.setup.v1"
    assert data["uv_extra"] in {"r2", "analyzers"}
    assert "brief" in data["agent"]["verbs"]


def test_brief_missing_file_is_nonzero() -> None:
    result = runner.invoke(app, ["brief", "/no/such/r2b-bin", "--quick", "--json"])
    assert result.exit_code == 1


def test_brief_json_stdout_is_briefing(tmp_path: Path) -> None:
    binary = tmp_path / "ls"
    binary.write_bytes(b"\x7fELF")
    result = _ls_result(binary)
    with (
        patch("r2b.cli.build_state", return_value=_state(tmp_path, result)),
        patch("r2b.cli._persist_record", return_value=None),
        patch("r2b.cli._publish_session", return_value=None),
    ):
        out = runner.invoke(app, ["brief", str(binary), "--quick", "--json"])
    assert out.exit_code == 0, out.output
    data = _json_payload(out.stdout)
    assert data["schema_version"] == "r2b.briefing.v1"
    assert data["overall_ask"]
    assert isinstance(data["regions"], list)
    assert data["handoff"]["schema_version"] == "r2b.handoff.v1"
    assert isinstance(data["handoff"]["next_argv"], list)
    assert all(cmd.startswith("r2b ") for cmd in data["handoff"]["next_argv"])
    assert not any(cmd.endswith("brief " + str(binary) + " --quick --json") for cmd in data["handoff"]["next_argv"])
    assert "ask" not in data["handoff"]
    assert "ask_result" not in data


def test_brief_defaults_to_quick_and_no_save_is_pure(tmp_path: Path) -> None:
    binary = tmp_path / "ls"
    binary.write_bytes(b"\x7fELF")
    analysis = _ls_result(binary)
    state = _state(tmp_path, analysis)
    with (
        patch("r2b.cli.build_state", return_value=state) as build,
        patch("r2b.cli._persist_record") as persist_record,
        patch("r2b.cli._publish_session") as publish_session,
    ):
        out = runner.invoke(app, ["brief", str(binary), "--no-save", "--json"])

    assert out.exit_code == 0, out.output
    build.assert_called_once_with(None, persist=False)
    state.orchestrator.create_plan.assert_called_once_with(quick_only=True, skip_deep=False)
    persist_record.assert_not_called()
    publish_session.assert_not_called()


def test_ask_empty_exits_2_and_keeps_json_stdout(tmp_path: Path) -> None:
    binary = tmp_path / "ls"
    binary.write_bytes(b"\x7fELF")
    result = _ls_result(binary)
    stub = MagicMock()
    stub.chat.return_value = ""
    stub.last_provider = "openai"
    with (
        patch("r2b.cli.build_state", return_value=_state(tmp_path, result)),
        patch("r2b.cli._persist_record", return_value=None),
        patch("r2b.cli._publish_session", return_value=None),
        patch("r2b.cli.LLMBridge", return_value=stub),
    ):
        out = runner.invoke(app, ["brief", str(binary), "--quick", "--json", "--ask"])
    assert out.exit_code == 2, out.output
    data = _json_payload(out.stdout)
    assert data["schema_version"] == "r2b.briefing.v1"
    assert data["ask_result"]["ok"] is False
    assert data["ask_result"]["answers"][0]["text"] == ""
    assert stub.chat.call_count >= 2


def test_ask_cited_reply_does_not_break_json(tmp_path: Path) -> None:
    binary = tmp_path / "ls"
    binary.write_bytes(b"\x7fELF")
    result = _ls_result(binary)
    stub = MagicMock()
    stub.chat.return_value = (
        "- strcpy at PLT is the first region [tool=radare2 addr=0x7a8 artifact=imports:plt xref=strcpy]"
    )
    stub.last_provider = "openai"
    with (
        patch("r2b.cli.build_state", return_value=_state(tmp_path, result)),
        patch("r2b.cli._persist_record", return_value=None),
        patch("r2b.cli._publish_session", return_value=None),
        patch("r2b.cli.LLMBridge", return_value=stub),
    ):
        out = runner.invoke(app, ["brief", str(binary), "--quick", "--json", "--ask"])
    assert out.exit_code == 0, out.output
    data = _json_payload(out.stdout)
    assert data["schema_version"] == "r2b.briefing.v1"
    stub.chat.assert_called_once()
    assert data["ask_result"]["ok"] is True
    assert data["ask_result"]["answers"][0]["cited"]["claims"]
    assert "ask" not in data["handoff"]


def test_brief_json_stdout_is_one_object_with_real_persist(tmp_path: Path) -> None:
    binary = tmp_path / "ls"
    binary.write_bytes(b"\x7fELF")
    result = _ls_result(binary)
    with patch("r2b.cli.build_state", return_value=_state(tmp_path, result)):
        out = runner.invoke(app, ["brief", str(binary), "--quick", "--json"])
    assert out.exit_code == 0, out.output
    data = json.loads(out.stdout)
    assert data["schema_version"] == "r2b.briefing.v1"
    assert data["handoff"]["schema_version"] == "r2b.handoff.v1"
    assert "Record" not in out.stdout
    assert "Session" not in out.stdout


def test_briefing_schema_required_includes_handoff() -> None:
    schema = json.loads(Path("schemas/briefing.schema.json").read_text())
    assert "handoff" in schema["required"]


def test_help_lists_brief_first_and_hides_pilot() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    text = result.stdout
    assert "brief" in text
    assert "pilot" not in text.lower()
    commands = text.split("Commands")[-1].lower()
    assert "analyze" not in commands
    brief_at = text.find("brief")
    verify_at = text.find("verify")
    assert 0 <= brief_at < verify_at


def test_decompile_does_not_open_the_record_database(tmp_path: Path) -> None:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x7fELF")
    state = MagicMock()
    state.env.ghidra.headless_ready = True
    adapter = MagicMock()
    adapter.decompile_function.return_value = {"success": True, "c": "int main(void) {}"}

    with (
        patch("r2b.cli.build_state", return_value=state) as build,
        patch("r2b.adapters.ghidra.GhidraAdapter", return_value=adapter),
    ):
        out = runner.invoke(app, ["decompile", str(binary), "0x1000", "--json"])

    assert out.exit_code == 0, out.output
    build.assert_called_once_with(None, persist=False)


def test_analyze_json_emits_briefing(tmp_path: Path) -> None:
    binary = tmp_path / "ls"
    binary.write_bytes(b"\x7fELF")
    result = _ls_result(binary)
    with (
        patch("r2b.cli.build_state", return_value=_state(tmp_path, result)),
        patch("r2b.cli._persist_record", return_value=None),
        patch("r2b.cli._publish_session", return_value=None),
    ):
        out = runner.invoke(app, ["analyze", str(binary), "--quick", "--json"])
    assert out.exit_code == 0, out.output
    data = json.loads(out.stdout)
    assert data["schema_version"] == "r2b.briefing.v1"
    assert data["handoff"]["schema_version"] == "r2b.handoff.v1"
    assert "ask" not in data["handoff"]
