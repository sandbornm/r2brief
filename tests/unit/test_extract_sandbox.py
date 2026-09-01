from pathlib import Path

from r2b.extract.sandbox import ExtractLimits, enforce_limits, run_sandboxed


def test_enforce_limits_prunes_extracted_files_keeps_root_json(tmp_path: Path) -> None:
    log = tmp_path / "binwalk3.json"
    log.write_text("[]", encoding="utf-8")
    extracted = tmp_path / "blob.extracted" / "0"
    extracted.mkdir(parents=True)
    kept = extracted / "keep.bin"
    kept.write_bytes(b"keep")
    extra = extracted / "drop.bin"
    extra.write_bytes(b"x" * 200)

    notes = enforce_limits(tmp_path, ExtractLimits(max_files=1, max_bytes=64))

    assert log.is_file()
    assert kept.is_file() or extra.is_file()
    remaining = [p for p in tmp_path.rglob("*") if p.is_file() and p != log]
    assert len(remaining) <= 1
    assert remaining[0].stat().st_size <= 64
    assert any("pruned" in note for note in notes)


def test_enforce_limits_noop_when_under_cap(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"abc")
    notes = enforce_limits(tmp_path, ExtractLimits(max_files=10, max_bytes=1024))
    assert notes == []
    assert (tmp_path / "a.bin").is_file()


def test_sandbox_path_includes_absolute_tool_directory(tmp_path: Path) -> None:
    tool_dir = tmp_path / "homebrew" / "bin"
    tool_dir.mkdir(parents=True)
    helper = tool_dir / "helper"
    helper.write_text("#!/bin/sh\nprintf helper-found\n", encoding="utf-8")
    helper.chmod(0o755)
    tool = tool_dir / "extractor"
    tool.write_text("#!/bin/sh\nhelper\n", encoding="utf-8")
    tool.chmod(0o755)
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"fixture")

    result = run_sandboxed(
        [str(tool)],
        input_file=subject,
        output_dir=tmp_path / "out",
    )

    assert result.returncode == 0
    assert result.stdout == "helper-found"
