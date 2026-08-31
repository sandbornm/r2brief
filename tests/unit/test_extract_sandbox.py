from pathlib import Path

from r2b.extract.sandbox import ExtractLimits, enforce_limits


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
