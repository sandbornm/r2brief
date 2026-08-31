from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from r2b.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2b.bundle import (
    BUNDLE_EXTENSION,
    BUNDLE_MEDIA_TYPE,
    BUNDLE_SCHEMA_VERSION,
    BundleError,
    create_bundle,
    default_bundle_path,
    inspect_bundle,
    read_bundle,
)
from r2b.cli import app
from r2b.config import AppConfig
from r2b.state import AppState


runner = CliRunner()


def _briefing(*, requires_scope: bool = False) -> dict:
    return {
        "schema_version": "r2b.briefing.v1",
        "binary": "/lab/challenge.bin",
        "subject": {"subject_class": "linux_elf"},
        "summary": "One imported sink and one caller.",
        "regions": [],
        "overall_ask": "Confirm the caller evidence.",
        "next_steps": [],
        "handoff": {
            "schema_version": "r2b.handoff.v1",
            "requires_scope": requires_scope,
            "next_argv": [],
        },
    }


def _analysis() -> dict:
    return {
        "type": "analysis_result",
        "schema_version": "r2b.analysis_result.v1",
        "binary": "/lab/challenge.bin",
        "quick_scan": {"radare2": {"imports": [{"name": "strcpy"}]}},
        "deep_scan": {},
        "tool_status": {"radare2": {"status": "ok", "version": "5.9"}},
        "provenance": {"profile": "triage", "commands": ["r2 -q -c ij challenge.bin"]},
    }


def _review() -> dict:
    return {
        "schema_version": "r2b.review-set.v1",
        "briefing": {"sha256": "ab" * 32},
        "overlay": {"unique_top_regions": 2},
    }


def test_bundle_is_deterministic_and_excludes_target_by_default(tmp_path: Path) -> None:
    target = tmp_path / "challenge.bin"
    target.write_bytes(b"\x7fELF\x00portable-evidence")
    first = tmp_path / f"first{BUNDLE_EXTENSION}"
    second = tmp_path / f"second{BUNDLE_EXTENSION}"

    one = create_bundle(first, briefing=_briefing(requires_scope=True), analysis=_analysis(), target=target)
    two = create_bundle(second, briefing=_briefing(requires_scope=True), analysis=_analysis(), target=target)

    assert first.read_bytes() == second.read_bytes()
    assert one.sha256 == two.sha256 == hashlib.sha256(first.read_bytes()).hexdigest()
    assert one.manifest["schema_version"] == BUNDLE_SCHEMA_VERSION
    assert one.manifest["requires_scope"] is True
    assert one.provenance == _analysis()["provenance"]
    assert one.manifest["subject"] == {
        "name": "challenge.bin",
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "size": len(target.read_bytes()),
        "bytes_included": False,
    }
    assert "target.bin" not in one.summary()["members"]
    with zipfile.ZipFile(first) as archive:
        assert sorted(archive.namelist()) == [
            "analysis.json",
            "briefing.json",
            "manifest.json",
            "mimetype",
            "provenance.json",
            "tools.json",
        ]
        sentinel = archive.infolist()[0]
        assert sentinel.filename == "mimetype"
        assert sentinel.compress_type == zipfile.ZIP_STORED
        assert sentinel.extra == b""
        assert archive.read(sentinel) == BUNDLE_MEDIA_TYPE.encode("ascii")


def test_bundle_can_explicitly_include_target(tmp_path: Path) -> None:
    target = tmp_path / "challenge.exe"
    target.write_bytes(b"MZ\x90\x00")
    output = tmp_path / "challenge.r2br"

    created = create_bundle(
        output,
        briefing=_briefing(),
        analysis=_analysis(),
        target=target,
        include_target=True,
    )
    loaded = read_bundle(output)

    assert created.manifest["subject"]["member"] == "target.bin"
    assert loaded.summary()["target_included"] is True
    with zipfile.ZipFile(output) as archive:
        assert archive.read("target.bin") == target.read_bytes()


def test_bundle_can_attach_review_overlay(tmp_path: Path) -> None:
    target = tmp_path / "challenge"
    target.write_bytes(b"sample")
    output = tmp_path / "reviewed.r2br"

    created = create_bundle(
        output,
        briefing=_briefing(),
        analysis=_analysis(),
        review=_review(),
        target=target,
    )

    assert created.review == _review()
    assert "review.json" in created.summary()["members"]
    with zipfile.ZipFile(output) as archive:
        assert json.loads(archive.read("review.json")) == _review()


def test_read_sniffs_manifest_not_filename_extension(tmp_path: Path) -> None:
    target = tmp_path / "sample"
    target.write_bytes(b"sample")
    output = tmp_path / "portable.data"
    create_bundle(output, briefing=_briefing(), analysis=_analysis(), target=target)

    summary = inspect_bundle(output)

    assert summary["schema_version"] == BUNDLE_SCHEMA_VERSION
    assert summary["path"].endswith("portable.data")
    assert default_bundle_path(tmp_path / "sample.exe").name == "sample.r2br"
    assert default_bundle_path(tmp_path / "sample").name == "sample.r2br"


def test_generic_zip_renamed_r2br_is_rejected(tmp_path: Path) -> None:
    output = tmp_path / "generic.r2br"
    with zipfile.ZipFile(output, mode="w") as archive:
        archive.writestr("notes.txt", b"this is only a zip")

    with pytest.raises(BundleError, match="mimetype"):
        read_bundle(output)


def test_read_rejects_member_hash_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "sample"
    target.write_bytes(b"sample")
    output = tmp_path / "sample.r2br"
    create_bundle(output, briefing=_briefing(), analysis=_analysis(), target=target)

    with zipfile.ZipFile(output) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members["briefing.json"] = b'{"schema_version":"r2b.briefing.v1"}\n'
    with zipfile.ZipFile(output, mode="w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)

    with pytest.raises(BundleError, match="hash validation"):
        read_bundle(output)


def test_read_rejects_path_traversal(tmp_path: Path) -> None:
    output = tmp_path / "hostile.r2br"
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "container": "zip",
        "producer": {"name": "r2b", "version": "0.1.0"},
        "subject": {"name": "x", "sha256": None, "size": None, "bytes_included": False},
        "entries": [],
    }
    with zipfile.ZipFile(output, mode="w") as archive:
        archive.writestr("mimetype", BUNDLE_MEDIA_TYPE)
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("../escape", b"nope")

    with pytest.raises(BundleError, match="unsafe or unknown"):
        read_bundle(output)


def test_create_rejects_unversioned_briefing(tmp_path: Path) -> None:
    with pytest.raises(BundleError, match="schema_version"):
        create_bundle(
            tmp_path / "bad.r2br",
            briefing={"binary": "x"},
            analysis=_analysis(),
        )


def test_manifest_schema_tracks_bundle_contract() -> None:
    schema = json.loads(Path("schemas/evidence_bundle.schema.json").read_text())
    assert schema["properties"]["schema_version"]["const"] == BUNDLE_SCHEMA_VERSION
    assert schema["properties"]["subject"]["properties"]["member"]["const"] == "target.bin"
    assert "provenance.json" in schema["properties"]["entries"]["items"]["properties"]["path"]["enum"]
    assert "review.json" in schema["properties"]["entries"]["items"]["properties"]["path"]["enum"]


def test_bundle_cli_create_then_inspect(tmp_path: Path) -> None:
    target = tmp_path / "challenge.bin"
    target.write_bytes(b"\x7fELF")
    output = tmp_path / "portable.r2br"
    analysis = AnalysisResult(
        binary=target,
        plan=AnalysisPlan(quick=True, deep=False, persist_trajectory=False, profile="triage"),
        quick_scan={
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 64, "os": "linux"}},
                "imports": [{"name": "strcpy"}],
            }
        },
        tool_status={"radare2": {"status": "ok"}},
    )
    orchestrator = MagicMock()
    orchestrator.create_plan.return_value = analysis.plan
    orchestrator.analyze.return_value = analysis
    config = AppConfig()
    state = AppState(
        config=config,
        env=MagicMock(),
        dao=None,
        chat_dao=None,
        orchestrator=orchestrator,
        db=None,
    )

    with patch("r2b.cli.build_state", return_value=state) as build:
        created = runner.invoke(
            app,
            ["bundle", "create", str(target), "-o", str(output), "--json"],
        )
    assert created.exit_code == 0, created.output
    build.assert_called_once_with(None, persist=False)
    create_summary = json.loads(created.stdout)
    assert create_summary["target_included"] is False
    assert output.is_file()

    inspected = runner.invoke(app, ["bundle", "inspect", str(output), "--json"])
    assert inspected.exit_code == 0, inspected.output
    assert json.loads(inspected.stdout)["bundle_sha256"] == create_summary["bundle_sha256"]
