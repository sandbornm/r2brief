"""Contract tests for verify JSON, handoff regions, and CLI error paths."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from r2b.analysis.briefing import build_handoff
from r2b.analysis.verify import CallSite, ImportVerdict, verify_imports
from r2b.bundle import BundleError, create_bundle, inspect_bundle, read_bundle
from r2b.cli import app

runner = CliRunner()


REQUIRED_VERIFY_SITE_KEYS = {
    "function",
    "function_addr",
    "address",
    "argument",
    "constant",
}


def test_verify_verdict_dict_has_stable_schema() -> None:
    verdict = ImportVerdict(
        import_name="sprintf",
        call_sites=[
            CallSite(
                function="replace_str",
                function_addr="0x00032ef8",
                address="0x00032f88",
                argument="<dynamic>",
                is_constant=False,
            )
        ],
    )
    payload = verdict.to_dict()
    assert payload["import"] == "sprintf"
    assert payload["status"] == "dynamic"
    site = payload["call_sites"][0]
    assert REQUIRED_VERIFY_SITE_KEYS <= set(site)
    assert site["function_addr"] == "0x00032ef8"
    assert site["constant"] is False


def test_verify_imports_empty_windows_yield_no_callers() -> None:
    verdicts = verify_imports({"system": []}, arch="mips")
    assert len(verdicts) == 1
    assert verdicts[0].status == "no-callers"
    assert verdicts[0].to_dict()["call_sites"] == []


def test_handoff_exposes_region_addr_and_next_argv_list() -> None:
    briefing = {
        "schema_version": "r2b.briefing.v1",
        "binary": "/lab/lighttpd",
        "summary": "One sink.",
        "regions": [
            {
                "id": "r1",
                "title": "sprintf in replace_str",
                "why": "unbounded format sink",
                "tags": ["import:sprintf"],
                "snippet": {"address": "0x00032f2c", "text": "bl sym.imp.sprintf\n"},
                "next_actions": [],
            }
        ],
        "overall_ask": "Confirm the sink.",
        "next_steps": [],
        "subject": {
            "name": "lighttpd",
            "format": "elf",
            "arch": "arm",
            "stripped": True,
            "dangerous_imports": ["sprintf", "system"],
            "risk_level": "high",
            "subject_class": "linux_elf",
            "size_bytes": 208740,
        },
    }
    handoff = build_handoff(briefing, record_id="abcd" * 8)
    assert handoff["schema_version"] == "r2b.handoff.v1"
    assert isinstance(handoff["next_argv"], list)
    assert handoff["regions"][0]["addr"] == "0x00032f2c"
    # Empty next_argv is valid when requires_scope; here we expect verify cmds or records.
    assert all(isinstance(cmd, str) for cmd in handoff["next_argv"])


def test_handoff_empty_next_argv_when_requires_scope() -> None:
    briefing = {
        "binary": "/lab/fw.bin",
        "summary": "Broad firmware.",
        "regions": [],
        "subject": {
            "name": "fw.bin",
            "subject_class": "firmware_container",
            "triage_scope": "broad",
            "dangerous_imports": [],
        },
    }
    handoff = build_handoff(briefing)
    assert handoff["requires_scope"] is True
    assert handoff["next_argv"] == []


def test_verify_cli_missing_binary_exits_1() -> None:
    out = runner.invoke(app, ["verify", "/no/such/binary", "--import", "strcpy", "--json"])
    assert out.exit_code == 1


def test_verify_cli_rejects_blank_import_name(tmp_path: Path) -> None:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x7fELF")
    adapter = MagicMock()
    adapter.verify_scan.return_value = []
    with (
        patch("r2b.cli.load_config"),
        patch("r2b.adapters.radare2.Radare2Adapter", return_value=adapter),
    ):
        out = runner.invoke(app, ["verify", str(binary), "--import", "  ", "--json"])
    assert out.exit_code == 0, out.output
    data = json.loads(out.stdout)
    assert data["schema_version"] == "r2b.verify.v1"
    assert data["verdicts"] == []
    # Blank import should not be forwarded.
    assert adapter.verify_scan.call_args.args[1] == []


def test_bundle_inspect_missing_file_exits_1(tmp_path: Path) -> None:
    out = runner.invoke(app, ["bundle", "inspect", str(tmp_path / "missing.r2br"), "--json"])
    assert out.exit_code == 1


def test_bundle_round_trip_preserves_briefing_and_subject_hash(tmp_path: Path) -> None:
    target = tmp_path / "lighttpd"
    target.write_bytes(b"\x7fELF" + b"replace_str-guard")
    briefing = {
        "schema_version": "r2b.briefing.v1",
        "binary": str(target),
        "summary": "Sink present.",
        "regions": [],
        "overall_ask": "Confirm.",
        "next_steps": [],
        "handoff": {
            "schema_version": "r2b.handoff.v1",
            "requires_scope": False,
            "next_argv": [],
            "regions": [{"id": "r1", "addr": "0x32f2c"}],
        },
    }
    analysis = {
        "type": "analysis_result",
        "schema_version": "r2b.analysis_result.v1",
        "binary": str(target),
        "quick_scan": {"radare2": {"imports": [{"name": "sprintf"}]}},
        "deep_scan": {},
        "tool_status": {"radare2": {"status": "ok"}},
        "provenance": {"profile": "triage", "commands": []},
    }
    output = tmp_path / "lighttpd.r2br"
    created = create_bundle(output, briefing=briefing, analysis=analysis, target=target)
    loaded = read_bundle(output)
    summary = inspect_bundle(output)

    assert created.sha256 == summary["bundle_sha256"]
    assert loaded.briefing["handoff"]["regions"][0]["addr"] == "0x32f2c"
    assert summary["subject"]["sha256"] == created.manifest["subject"]["sha256"]
    assert summary["target_included"] is False


def test_bundle_create_cli_missing_binary_exits_1() -> None:
    out = runner.invoke(app, ["bundle", "create", "/no/such/bin", "--json"])
    assert out.exit_code == 1
