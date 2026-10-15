"""Optional post-verify gadget scan."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from r2b.analysis.gadgets import GADGETS_SCHEMA_VERSION, scan_gadgets, _parse_gadget_lines


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

    class Result:
        returncode = 0
        stdout = "0x401000: ret\n0x401010: pop rax; ret\n"
        stderr = ""

    def fake_which(name: str):
        return "/usr/bin/radare2" if name == "radare2" else None

    with (
        patch("r2b.analysis.gadgets.shutil.which", side_effect=fake_which),
        patch("r2b.analysis.gadgets.subprocess.run", return_value=Result()),
    ):
        payload = scan_gadgets(binary, limit=10)
    assert payload["status"] == "ok"
    assert payload["engine"] == "radare2"
    assert payload["count"] == 2
    assert payload["gadgets"][0]["address"].startswith("0x")
