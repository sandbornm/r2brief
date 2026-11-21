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
        limits=ExtractLimits(allow_unsafe_fallback=True),
    )

    assert result.returncode == 0
    assert result.stdout == "helper-found"


def test_sandbox_fails_closed_without_bubblewrap(tmp_path: Path, monkeypatch) -> None:
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"fixture")
    marker = tmp_path / "ran"
    monkeypatch.setattr("r2b.extract.sandbox.shutil.which", lambda _name: None)

    result = run_sandboxed(
        ["/bin/sh", "-c", f"touch {marker}"],
        input_file=subject,
        output_dir=tmp_path / "out",
    )

    assert result.returncode == 126
    assert result.sandbox == "unavailable"
    assert not marker.exists()
    assert any("blocked" in note for note in result.notes)


def test_sandbox_stops_extractor_that_crosses_live_file_cap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    tool = tmp_path / "extractor"
    tool.write_text(
        "#!/bin/sh\ni=0\nwhile [ $i -lt 10 ]; do printf x > file-$i; i=$((i+1)); done\nsleep 2\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"fixture")
    monkeypatch.setattr("r2b.extract.sandbox.shutil.which", lambda _name: None)

    result = run_sandboxed(
        [str(tool)],
        input_file=subject,
        output_dir=tmp_path / "out",
        limits=ExtractLimits(max_files=2, allow_unsafe_fallback=True),
    )

    assert result.returncode == 125
    assert any("live output limit" in note for note in result.notes)
    assert len([path for path in result.output_dir.rglob("*") if path.is_file()]) <= 2


def test_bwrap_argv_binds_absolute_tool_directory_read_only(tmp_path: Path) -> None:
    from r2b.extract.sandbox import _bwrap_argv

    tool_dir = tmp_path / "prefix" / "bin"
    tool_dir.mkdir(parents=True)
    tool = tool_dir / "extractor"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"fixture")
    out = tmp_path / "out"
    out.mkdir()

    argv = _bwrap_argv("bwrap", [str(tool)], input_file=subject, output_dir=out, extra_ro_binds=None)

    resolved = str(tool_dir.resolve())
    triples = list(zip(argv, argv[1:], argv[2:]))
    assert ("--ro-bind", resolved, resolved) in triples
    assert ("--bind", resolved, resolved) not in triples
    assert argv.index("--tmpfs") < argv.index(resolved)


def test_bwrap_argv_does_not_rebind_system_tool_directory(tmp_path: Path) -> None:
    from r2b.extract.sandbox import _bwrap_argv

    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"fixture")
    out = tmp_path / "out"
    out.mkdir()

    argv = _bwrap_argv("bwrap", ["/bin/sh"], input_file=subject, output_dir=out, extra_ro_binds=None)

    assert argv.count("/bin") <= 2



def test_bwrap_argv_does_not_bind_home_directory(tmp_path: Path, monkeypatch) -> None:
    from r2b.extract.sandbox import _bwrap_argv

    home = tmp_path / "home"
    home.mkdir()
    tool = home / "extractor"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"fixture")
    out = tmp_path / "out"
    out.mkdir()

    argv = _bwrap_argv("bwrap", [str(tool)], input_file=subject, output_dir=out, extra_ro_binds=None)

    triples = list(zip(argv, argv[1:], argv[2:]))
    home_s = str(home.resolve())
    tool_s = str(tool.resolve())
    assert ("--ro-bind", home_s, home_s) not in triples
    assert ("--ro-bind", tool_s, tool_s) in triples


def test_bwrap_argv_resolves_symlinked_extractor(tmp_path: Path) -> None:
    from r2b.extract.sandbox import _bwrap_argv

    real_dir = tmp_path / "prefix" / "bin"
    real_dir.mkdir(parents=True)
    tool = real_dir / "extractor"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    link_dir = tmp_path / "link-bin"
    link_dir.mkdir()
    link = link_dir / "extractor"
    link.symlink_to(tool)
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"fixture")
    out = tmp_path / "out"
    out.mkdir()

    argv = _bwrap_argv("bwrap", [str(link)], input_file=subject, output_dir=out, extra_ro_binds=None)
    triples = list(zip(argv, argv[1:], argv[2:]))
    resolved_dir = str(real_dir.resolve())
    resolved_tool = str(tool.resolve())
    assert ("--ro-bind", resolved_dir, resolved_dir) in triples or (
        "--ro-bind",
        resolved_tool,
        resolved_tool,
    ) in triples
    assert ("--ro-bind", str(link_dir.resolve()), str(link_dir.resolve())) not in triples
    dash = argv.index("--")
    assert argv[dash + 1] == resolved_tool



def test_bwrap_argv_does_not_bind_home_project_directory(tmp_path: Path, monkeypatch) -> None:
    from r2b.extract.sandbox import _bwrap_argv

    home = tmp_path / "home"
    proj = home / "proj"
    proj.mkdir(parents=True)
    tool = proj / "extractor"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    subject = tmp_path / "subject.bin"
    subject.write_bytes(b"fixture")
    out = tmp_path / "out"
    out.mkdir()

    argv = _bwrap_argv("bwrap", [str(tool)], input_file=subject, output_dir=out, extra_ro_binds=None)
    triples = list(zip(argv, argv[1:], argv[2:]))
    proj_s = str(proj.resolve())
    tool_s = str(tool.resolve())
    assert ("--ro-bind", proj_s, proj_s) not in triples
    assert ("--ro-bind", tool_s, tool_s) in triples
