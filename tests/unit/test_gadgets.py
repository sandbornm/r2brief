"""Optional post-verify gadget scan."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from r2b.analysis.gadgets import (
    GADGETS_SCHEMA_VERSION,
    preferred_radare2_rop_command,
    scan_gadgets,
    _parse_gadget_lines,
)


def test_parse_gadget_lines_are_bounded_and_sorted() -> None:
    text = """
0x00002010 : pop rdi ; ret
0x00001000 : ret
0x00002010 : pop rdi ; ret
Gadgets information
"""
    hits = _parse_gadget_lines(text, limit=2)
    assert len(hits) == 2
    assert hits[0].address == "0x00001000"
    assert hits[1].instructions.startswith("pop rdi")


def test_scan_gadgets_missing_binary(tmp_path: Path) -> None:
    payload = scan_gadgets(tmp_path / "nope.bin")
    assert payload["schema_version"] == GADGETS_SCHEMA_VERSION
    assert payload["status"] == "missing"
    assert payload["gadgets"] == []


def test_scan_gadgets_skipped_without_engines(tmp_path: Path) -> None:
    binary = tmp_path / "t.bin"
    binary.write_bytes(b"\x7fELF")
    with patch("r2b.analysis.gadgets.shutil.which", return_value=None):
        payload = scan_gadgets(binary, limit=4)
    assert payload["status"] == "skipped"
    assert payload["engine"] is None
    assert payload["limit"] == 4


def test_scan_gadgets_uses_radare2_when_present(tmp_path: Path) -> None:
    binary = tmp_path / "t.bin"
    binary.write_bytes(b"\x7fELF")

    class VersionResult:
        returncode = 0
        stdout = "radare2 6.0.5\n"
        stderr = ""

    class Result:
        returncode = 0
        stdout = "0x401000: ret\n0x401010: pop rax; ret\n"
        stderr = ""

    def fake_which(name: str):
        return "/usr/bin/radare2" if name == "radare2" else None

    def fake_run(cmd, **kwargs):
        if "-v" in cmd:
            return VersionResult()
        return Result()

    with (
        patch("r2b.analysis.gadgets.shutil.which", side_effect=fake_which),
        patch("r2b.analysis.gadgets.subprocess.run", side_effect=fake_run),
    ):
        payload = scan_gadgets(binary, limit=10)
    assert payload["status"] == "ok"
    assert payload["engine"] == "radare2"
    assert payload["count"] == 2
    assert payload["gadgets"][0]["address"].startswith("0x")


def test_radare2_version_prefers_R_before_6_2() -> None:
    assert preferred_radare2_rop_command("radare2 6.0.5") == "/R"
    assert preferred_radare2_rop_command("radare2 5.8.8") == "/R"
    assert preferred_radare2_rop_command("radare2 6.2.4") == "/g"


def test_radare2_rejected_R_falls_back_to_slash_g(tmp_path: Path) -> None:
    """Regression: '/R is now known as /g' must retry /g, never ok+0 on reject."""
    binary = tmp_path / "t.bin"
    binary.write_bytes(b"\x7fELF")

    class VersionResult:
        returncode = 0
        stdout = "radare2 6.0.5\n"  # prefer /R first
        stderr = ""

    class RejectR:
        returncode = 0
        stdout = ""
        stderr = "/R is now known as /g\n"

    class OkG:
        returncode = 0
        stdout = "0x401000: ret\n"
        stderr = ""

    calls: list[list[str]] = []

    def fake_which(name: str):
        return "/usr/bin/radare2" if name == "radare2" else None

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        joined = " ".join(cmd)
        if "-v" in cmd:
            return VersionResult()
        # Match the -c argument exactly
        if "-c" in cmd:
            idx = cmd.index("-c")
            rop_cmd = cmd[idx + 1]
            if rop_cmd == "/R":
                return RejectR()
            if rop_cmd == "/g":
                return OkG()
        return RejectR()

    with (
        patch("r2b.analysis.gadgets.shutil.which", side_effect=fake_which),
        patch("r2b.analysis.gadgets.subprocess.run", side_effect=fake_run),
    ):
        payload = scan_gadgets(binary, limit=8)
    assert payload["status"] == "ok"
    assert payload["engine"] == "radare2"
    assert payload["count"] == 1
    assert any(c[c.index("-c") + 1] == "/g" for c in calls if "-c" in c)


def test_radare2_rejected_command_alone_is_not_ok(tmp_path: Path) -> None:
    """Regression: rename reject with no usable fallback → failed/unsupported, not ok."""
    binary = tmp_path / "t.bin"
    binary.write_bytes(b"\x7fELF")

    class VersionResult:
        returncode = 0
        stdout = "radare2 6.2.4\n"
        stderr = ""

    class Reject:
        returncode = 0
        stdout = ""
        stderr = "/R is now known as /g\n"

    def fake_which(name: str):
        return "/usr/bin/radare2" if name == "radare2" else None

    def fake_run(cmd, **kwargs):
        if "-v" in cmd:
            return VersionResult()
        return Reject()

    with (
        patch("r2b.analysis.gadgets.shutil.which", side_effect=fake_which),
        patch("r2b.analysis.gadgets.subprocess.run", side_effect=fake_run),
    ):
        payload = scan_gadgets(binary, limit=4)
    assert payload["status"] in {"failed", "unsupported"}
    assert payload["count"] == 0
    assert payload["gadgets"] == []
