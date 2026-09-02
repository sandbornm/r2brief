from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from r2b.adapters.base import AdapterUnavailable
from r2b.adapters.ghidra import GhidraAdapter
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
