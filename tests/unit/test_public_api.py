from __future__ import annotations

from pathlib import Path

import pytest

import r2b
from r2b import AnalysisOptions
from r2b.analysis.orchestrator import AnalysisPlan, AnalysisResult


def test_public_surface_is_r2b() -> None:
    assert callable(r2b.analyze)
    assert callable(r2b.ask)
    assert callable(r2b.brief)
    assert callable(r2b.review)
    assert callable(r2b.verify)
    assert r2b.AnalysisReport.__module__ == "r2b.api"


def test_options_reject_invalid_profile_and_region_count() -> None:
    with pytest.raises(ValueError, match="Unsupported analysis profile"):
        AnalysisOptions(profile="mystery")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_regions"):
        AnalysisOptions(max_regions=0)


def test_analyze_is_pure_by_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(b"\x7fELF" + b"\0" * 60)
    captured: dict[str, object] = {}

    class FakeOrchestrator:
        def __init__(self, config: object, env: object) -> None:
            captured["config"] = config
            captured["env"] = env

        def create_plan(self, *, quick_only: bool, profile: str) -> AnalysisPlan:
            captured["quick_only"] = quick_only
            captured["profile"] = profile
            return AnalysisPlan(quick=True, deep=False, persist_trajectory=False, profile=profile)

        def analyze(self, path: Path, plan: AnalysisPlan) -> AnalysisResult:
            return AnalysisResult(
                binary=path,
                plan=plan,
                quick_scan={"sniff": {"format": "elf"}},
            )

    monkeypatch.setattr("r2b.api.detect_environment", lambda config: object())
    monkeypatch.setattr("r2b.api.AnalysisOrchestrator", FakeOrchestrator)

    report = r2b.analyze(binary)

    assert captured["quick_only"] is True
    assert captured["profile"] == "triage"
    assert captured["config"].analysis.enable_trajectory_recording is False  # type: ignore[union-attr]
    assert report.binary == binary.resolve()
    assert report.briefing["schema_version"] == "r2b.briefing.v1"
    assert report.payload["briefing"] == report.briefing


def test_analyze_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        r2b.analyze(tmp_path / "missing")


def test_ask_keeps_model_and_tools_opt_in(tmp_path: Path) -> None:
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(b"x")
    result = AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(quick=True, deep=False, persist_trajectory=False, profile="triage"),
    )
    report = r2b.AnalysisReport(
        result=result,
        payload={},
        briefing={
            "schema_version": "r2b.briefing.v1",
            "binary": str(binary),
            "summary": "tiny fixture",
            "subject": {},
            "regions": [],
            "overall_ask": "",
            "next_steps": [],
            "handoff": {"next_argv": []},
        },
    )

    class Bridge:
        def generate(self, messages: object, **kwargs: object) -> str:
            assert "What is this?" in list(messages)[1].content  # type: ignore[arg-type]
            assert kwargs["tools"] == ()
            assert kwargs["tool_executor"] is None
            return "answer"

    assert report.ask("What is this?", bridge=Bridge()) == "answer"
    with pytest.raises(ValueError, match="must not be empty"):
        r2b.ask(report, " ", bridge=Bridge())


def test_evidence_region_carries_scoped_context(tmp_path: Path) -> None:
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(b"x")
    result = AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(quick=True, deep=False, persist_trajectory=False, profile="triage"),
    )
    report = r2b.AnalysisReport(
        result=result,
        payload={},
        briefing={
            "schema_version": "r2b.briefing.v1",
            "binary": str(binary),
            "summary": "tiny fixture",
            "subject": {"format": "elf", "arch": "arm64/64"},
            "regions": [
                {
                    "id": "entry:main",
                    "title": "Entry / main",
                    "why": "first caller boundary",
                    "score": 89,
                    "snippet": {
                        "source": "radare2",
                        "address": "0x1000",
                        "function": "main",
                        "text": "0x1000 bl sym.imp.strcpy",
                    },
                    "next_actions": ["r2: `axt @ 0x1000`"],
                }
            ],
            "overall_ask": "",
            "next_steps": [],
            "handoff": {"next_argv": []},
        },
    )

    region = report.regions[0]
    assert region.id == "entry:main"
    assert region.evidence["source"] == "radare2"
    assert region.evidence["address"] == "0x1000"

    class Bridge:
        def generate(self, messages: object, **_kwargs: object) -> str:
            context = list(messages)[1].content  # type: ignore[arg-type]
            assert "Entry / main" in context
            assert "0x1000" in context
            return "scoped answer"

    assert region.ask("What supports this rank?", bridge=Bridge()) == "scoped answer"
