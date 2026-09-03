from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from r2b.adapters.base import AdapterUnavailable
from r2b.adapters.ghidra import (
    GhidraAdapter,
    _function_addr_from_decompile_c,
    resolve_decompile_function_va,
)
from r2b.config import GhidraSettings
from r2b.environment.ghidra import GhidraDetection


def test_decompile_function_requires_headless(tmp_path: Path):
    detection = GhidraDetection(
        install_dir=None,
        headless_path=None,
        bridge_available=False,
        bridge_connected=False,
        extension_root=tmp_path,
    )
    adapter = GhidraAdapter(
        detection=detection,
        project_dir=tmp_path / "proj",
        settings=GhidraSettings(),
    )
    with pytest.raises(AdapterUnavailable):
        adapter.decompile_function(tmp_path / "bin", "0x1000")


def test_headless_command_uses_extension_script_path(tmp_path: Path):
    script = tmp_path / "ext" / "scripts" / "R2BHeadless.java"
    script.parent.mkdir(parents=True)
    script.write_text("// fixture")
    detection = GhidraDetection(
        install_dir=tmp_path / "ghidra",
        headless_path=tmp_path / "ghidra" / "support" / "analyzeHeadless",
        bridge_available=False,
        bridge_connected=False,
        extension_root=tmp_path / "ext",
    )
    adapter = GhidraAdapter(
        detection=detection,
        project_dir=tmp_path / "proj",
        settings=GhidraSettings(),
    )

    result = adapter.deep_scan(tmp_path / "bin", dry_run=True)

    command = result["command"]
    assert command[command.index("-scriptPath") + 1] == str(script.parent)
    assert command[command.index("-postScript") + 1] == script.name


def test_decompile_function_expands_home_in_project_dir(tmp_path: Path):
    script = tmp_path / "ext" / "scripts" / "DecompileTargets.java"
    script.parent.mkdir(parents=True)
    script.write_text("// fixture")
    detection = GhidraDetection(
        install_dir=tmp_path / "ghidra",
        headless_path=tmp_path / "ghidra" / "support" / "analyzeHeadless",
        bridge_available=False,
        bridge_connected=False,
        extension_root=tmp_path / "ext",
    )
    project_dir = Path("~/.cache/r2b-tests/ghidra-eval")
    adapter = GhidraAdapter(
        detection=detection,
        project_dir=project_dir,
        settings=GhidraSettings(),
    )
    completed = MagicMock(returncode=0, stdout="ok", stderr="")
    expanded = project_dir.expanduser()
    try:
        with patch("r2b.adapters.ghidra.subprocess.run", return_value=completed) as run:
            adapter.decompile_function(tmp_path / "bin", "0x8048880")
        command = run.call_args.args[0]
        assert command[1] == str(expanded)
        assert "~" not in Path(command[1]).parts
    finally:
        if expanded.exists():
            for child in expanded.glob("*"):
                if child.is_file():
                    child.unlink()
            expanded.rmdir()


def test_resolve_decompile_function_va_prefers_containing_function(tmp_path: Path):
    binary = tmp_path / "ubusd"
    binary.write_bytes(b"\x7fELF")

    class FakeAdapter:
        def is_available(self) -> bool:
            return True

        def containing_function_va(self, path: Path, address: str) -> str:
            assert path == binary
            assert address == "0x4ba8"
            return "0x00004a3c"

    with patch("r2b.adapters.radare2.Radare2Adapter", return_value=FakeAdapter()):
        assert resolve_decompile_function_va(binary, "0x4ba8") == "0x00004a3c"


def test_resolve_decompile_function_va_falls_back_to_given_hex(tmp_path: Path):
    missing = tmp_path / "missing-bin"
    assert resolve_decompile_function_va(missing, "0x4a3c") == "0x00004a3c"
    assert resolve_decompile_function_va(missing, "fcn.00004a3c") == "0x00004a3c"


def test_function_addr_from_decompile_c_reads_ghidra_header():
    text = "// ==== FUN_00004a3c @ 0x4a3c ====\nint fun(void) { return 0; }\n"
    assert _function_addr_from_decompile_c(text) == "0x00004a3c"


def test_decompile_function_passes_containing_function_va(tmp_path: Path):
    script = tmp_path / "ext" / "scripts" / "DecompileTargets.java"
    script.parent.mkdir(parents=True)
    script.write_text("// fixture")
    binary = tmp_path / "ubusd"
    binary.write_bytes(b"\x7fELF")
    detection = GhidraDetection(
        install_dir=tmp_path / "ghidra",
        headless_path=tmp_path / "ghidra" / "support" / "analyzeHeadless",
        bridge_available=False,
        bridge_connected=False,
        extension_root=tmp_path / "ext",
    )
    adapter = GhidraAdapter(
        detection=detection,
        project_dir=tmp_path / "proj",
        settings=GhidraSettings(),
    )
    completed = MagicMock(returncode=0, stdout="ok", stderr="")

    def fake_run(command, **_kwargs):
        output = Path(command[-2])
        output.write_text("// ==== fcn.00004a3c @ 0x4a3c ====\nint fcn(void) { return 1; }\n")
        return completed

    with (
        patch(
            "r2b.adapters.ghidra.resolve_decompile_function_va",
            return_value="0x00004a3c",
        ),
        patch("r2b.adapters.ghidra.subprocess.run", side_effect=fake_run) as run,
    ):
        payload = adapter.decompile_function(binary, "0x4ba8")

    command = run.call_args.args[0]
    assert command[-1] == "00004a3c"
    assert payload["address"] == "0x00004ba8"
    assert payload["function_addr"] == "0x00004a3c"
    assert payload["success"] is True
    assert "int fcn" in payload["c"]


def test_decompile_function_reports_resolved_va_when_ghidra_has_no_function(tmp_path: Path):
    script = tmp_path / "ext" / "scripts" / "DecompileTargets.java"
    script.parent.mkdir(parents=True)
    script.write_text("// fixture")
    binary = tmp_path / "ubusd"
    binary.write_bytes(b"\x7fELF")
    detection = GhidraDetection(
        install_dir=tmp_path / "ghidra",
        headless_path=tmp_path / "ghidra" / "support" / "analyzeHeadless",
        bridge_available=False,
        bridge_connected=False,
        extension_root=tmp_path / "ext",
    )
    adapter = GhidraAdapter(
        detection=detection,
        project_dir=tmp_path / "proj",
        settings=GhidraSettings(),
    )
    completed = MagicMock(returncode=0, stdout="ok", stderr="")

    def fake_run(command, **_kwargs):
        output = Path(command[-2])
        output.write_text("// no function at 4ba8\n")
        return completed

    with (
        patch(
            "r2b.adapters.ghidra.resolve_decompile_function_va",
            return_value="0x00004a3c",
        ),
        patch("r2b.adapters.ghidra.subprocess.run", side_effect=fake_run),
    ):
        payload = adapter.decompile_function(binary, "0x4ba8")

    assert payload["success"] is False
    assert payload["function_addr"] == "0x00004a3c"
    assert "resolved containing function 0x00004a3c" in payload["c"]
