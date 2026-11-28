"""Path confinement, option validation and log hygiene for request-controlled values."""

from __future__ import annotations

import logging
import shlex
import subprocess
from pathlib import Path

import pytest

from r2b.compilation import compiler as comp
from r2b.utils.safety import (
    UnsafeInputError,
    reject_option_like,
    resolve_within,
    safe_stem,
    sanitize_log,
)


# --- resolve_within -------------------------------------------------------------------


def test_resolve_within_accepts_files_under_root(tmp_path: Path) -> None:
    target = tmp_path / "up" / "a.bin"
    target.parent.mkdir()
    target.write_bytes(b"x")
    assert resolve_within(target, [tmp_path / "up"]) == target.resolve()


def test_resolve_within_resolves_relative_paths_against_first_root(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"x")
    assert resolve_within("a.bin", [tmp_path]) == (tmp_path / "a.bin").resolve()


@pytest.mark.parametrize("candidate", ["../escape", "sub/../../escape", "/etc/passwd", "a\x00b"])
def test_resolve_within_rejects_escapes(tmp_path: Path, candidate: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(UnsafeInputError):
        resolve_within(candidate, [root])


def test_resolve_within_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret")
    (root / "link").symlink_to(secret)
    with pytest.raises(UnsafeInputError):
        resolve_within(root / "link", [root])


def test_resolve_within_rejects_sibling_with_shared_prefix(tmp_path: Path) -> None:
    root = tmp_path / "uploads"
    sibling = tmp_path / "uploads-evil"
    root.mkdir()
    sibling.mkdir()
    with pytest.raises(UnsafeInputError):
        resolve_within(sibling / "x", [root])


def test_resolve_within_without_roots_denies(tmp_path: Path) -> None:
    with pytest.raises(UnsafeInputError):
        resolve_within(tmp_path, [])


# --- small helpers --------------------------------------------------------------------


def test_safe_stem_strips_separators_extensions_and_leading_dashes() -> None:
    assert safe_stem("../../etc/passwd") == "passwd"
    assert safe_stem("my prog.out") == "my_prog"
    assert safe_stem("-oops") == "oops"
    assert safe_stem("a.b.c") == "a_b"
    assert safe_stem("///") == "output"
    assert safe_stem("") == "output"


def test_reject_option_like() -> None:
    assert reject_option_like("sample.bin") == "sample.bin"
    for bad in ("", "-import", "--foo", "a\x00b"):
        with pytest.raises(UnsafeInputError):
            reject_option_like(bad)


def test_sanitize_log_removes_line_breaks_and_truncates() -> None:
    forged = "ok\r\nERROR forged entry\nnext\x1b[31m"
    cleaned = sanitize_log(forged)
    assert "\n" not in cleaned and "\r" not in cleaned and "\x1b" not in cleaned
    assert cleaned.startswith("ok\\r\\nERROR forged entry")
    assert sanitize_log("a" * 1000, max_len=10) == "a" * 10 + "..."


def test_debug_log_request_keeps_one_record_per_call(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    from r2b.web import debug

    monkeypatch.setattr(debug, "DEBUG_ENABLED", True)
    with caplog.at_level(logging.DEBUG, logger="r2b.debug"):
        debug.log_request("api\nFORGED", "binary=/tmp/x\nINFO forged line", {"k": "v\nw"})
    assert len(caplog.records) == 1
    assert "\n" not in caplog.records[0].getMessage()


# --- compiler option validation -------------------------------------------------------


@pytest.mark.parametrize("opt", ["-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-Og"])
def test_valid_optimizations(opt: str) -> None:
    assert comp.validate_optimization(opt) == opt


@pytest.mark.parametrize(
    "opt",
    ["-O4", "-fplugin=/tmp/x.so", "-O0; touch /tmp/pwn", "-O0 -o /tmp/x", "", "--version", "-O0\n-c"],
)
def test_bad_optimizations_rejected(opt: str) -> None:
    with pytest.raises(UnsafeInputError):
        comp.validate_optimization(opt)


def test_flag_allowlist_accepts_known_flags() -> None:
    flags = ["-ffreestanding", "-nostdlib", "-static", "-std=c11", "-Wall", "-Wno-unused-variable", "-fno-pic"]
    assert comp.validate_extra_flags(flags) == flags
    assert comp.validate_extra_flags(None) == []


@pytest.mark.parametrize(
    "flag",
    [
        "-o",
        "-o/tmp/x",
        "-fplugin=/tmp/evil.so",
        "-specs=/tmp/evil.specs",
        "-Wl,--wrap=main",
        "-Xlinker",
        "-include",
        "-I/etc",
        "-DX=$(id)",
        "-march=armv8-a",
        "-std=c11; id",
        "-static; id",
        "--",
        "source.c",
    ],
)
def test_flags_outside_allowlist_rejected(flag: str) -> None:
    with pytest.raises(UnsafeInputError):
        comp.validate_extra_flags(["-static", flag])


@pytest.mark.parametrize("name", ["../x", "-x", "a b", "a;b", "a/b", "", "x" * 80, ".hidden"])
def test_bad_output_names_rejected(name: str) -> None:
    with pytest.raises(UnsafeInputError):
        comp.validate_output_name(name)


def test_architecture_allowlist() -> None:
    assert comp.validate_architecture("arm64") == "arm64"
    with pytest.raises(UnsafeInputError):
        comp.validate_architecture("arm64; id")


# --- docker path: nothing request-controlled can add shell syntax ---------------------


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):  # noqa: ANN001
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")


@pytest.fixture
def docker_stub(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    recorder = _Recorder()
    monkeypatch.setattr(comp, "_is_docker_available", lambda: True)
    monkeypatch.setattr(comp, "_docker_image_exists", lambda image: True)
    monkeypatch.setattr(comp.subprocess, "run", recorder)
    return recorder


def test_docker_compile_quotes_every_token(docker_stub: _Recorder) -> None:
    comp._compile_with_docker(
        "int main(void){return 0;}",
        "arm64",
        optimization="-O2",
        extra_flags=["-static", "-std=c11"],
        output_name="out_1",
    )
    assert docker_stub.calls, "docker was not invoked"
    for call in docker_stub.calls:
        assert call[:2] == ["docker", "run"]
        script = call[call.index("-c") + 1]
        tokens = shlex.split(script)
        assert tokens[0] == "aarch64-linux-gnu-gcc"
        assert tokens[-1] == "source.c"
        assert "-std=c11" in tokens and "-O2" in tokens
        # Re-quoting the parsed tokens must reproduce the script: no extra shell syntax.
        assert shlex.join(tokens) == script


@pytest.mark.parametrize(
    ("kwargs"),
    [
        {"optimization": "-O0; touch /tmp/pwn"},
        {"optimization": "-O0 $(id)"},
        {"extra_flags": ["-static; id"]},
        {"extra_flags": ["-fplugin=/tmp/x.so"]},
        {"output_name": "x; id"},
        {"output_name": "../../x"},
        {"architecture": "arm64; id"},
    ],
)
def test_docker_compile_rejects_injection_before_running_anything(docker_stub: _Recorder, kwargs: dict) -> None:
    params = {"source_code": "int main(void){return 0;}", "architecture": "arm64"}
    params.update(kwargs)
    result = comp._compile_with_docker(**params)
    assert result.success is False
    assert "Invalid compiler option" in result.stderr
    assert docker_stub.calls == []


# --- public entry points --------------------------------------------------------------


@pytest.fixture
def native_stub(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    recorder = _Recorder()
    gcc = comp.Compiler(name="gcc", path=Path("/usr/bin/gcc"), architecture="x86_64", is_clang=False)
    monkeypatch.setattr(
        comp,
        "detect_compilers",
        lambda: {"arm32": [], "arm64": [], "x86": [gcc], "x86_64": [gcc]},
    )
    monkeypatch.setattr(comp.subprocess, "run", recorder)
    return recorder


def test_compile_c_source_rejects_bad_options_without_running(native_stub: _Recorder) -> None:
    for kwargs in (
        {"optimization": "-fplugin=/tmp/x.so"},
        {"extra_flags": ["-o", "/tmp/clobber"]},
        {"architecture": "mips"},
    ):
        result = comp.compile_c_source("int main(void){return 0;}", **{"architecture": "x86_64", **kwargs})
        assert result.success is False
        assert "Invalid compiler option" in result.stderr
    assert native_stub.calls == []


def test_inline_source_is_code_even_when_it_names_a_file(tmp_path: Path, native_stub: _Recorder) -> None:
    secret = tmp_path / "secret.c"
    secret.write_text("int SECRET_FILE_CONTENT;")

    comp.compile_c_source(comp.InlineSource(str(secret)), "x86_64")
    comp.compile_to_asm(comp.InlineSource(str(secret)), "x86_64")

    assert len(native_stub.calls) == 2
    # The compiler was handed a temp file holding the literal string, not the secret file.
    for argv in native_stub.calls:
        assert str(secret) not in argv


def test_bare_string_source_keeps_library_behavior(tmp_path: Path, native_stub: _Recorder) -> None:
    src = tmp_path / "lib.c"
    src.write_text("int main(void){return 0;}")
    comp.compile_c_source(str(src), "x86_64")
    assert str(src.resolve()) in native_stub.calls[0]


def test_missing_path_source_reports_not_found(tmp_path: Path, native_stub: _Recorder) -> None:
    result = comp.compile_c_source(tmp_path / "nope.c", "x86_64")
    assert result.success is False and "not found" in result.stderr
    assert native_stub.calls == []


def test_native_compile_passes_absolute_source_path(tmp_path: Path, native_stub: _Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "-evil.c").write_text("int x;")
    comp.compile_c_source(Path("-evil.c"), "x86_64")
    argv = native_stub.calls[0]
    assert str(tmp_path / "-evil.c") in argv
    assert "-evil.c" not in argv


# --- SQL identifier allowlist ---------------------------------------------------------


def test_ensure_column_only_accepts_code_constant_identifiers(tmp_path: Path) -> None:
    import sqlite3

    from r2b.storage.db import Database, _ensure_column

    db = Database(tmp_path / "t.db")
    with sqlite3.connect(db.path) as conn:
        _ensure_column(conn, "function_names", "status", "TEXT")  # already present: no-op
        for table, column, decl in (
            ("function_names; DROP TABLE function_names", "x", "TEXT"),
            ("trajectories", "x", "TEXT"),
            ("function_names", "x; DROP TABLE function_names", "TEXT"),
            ("function_names", "x", "TEXT); DROP TABLE function_names; --"),
        ):
            with pytest.raises(ValueError):
                _ensure_column(conn, table, column, decl)
        assert conn.execute("SELECT count(*) FROM function_names").fetchone() is not None


def test_ghidra_setup_refuses_non_https_urls(tmp_path: Path) -> None:
    from r2b.environment.ghidra_setup import GhidraSetupError, download_archive

    for url in ("file:///etc/passwd", "ftp://example.com/x.zip", "http://example.com/x.zip"):
        with pytest.raises(GhidraSetupError, match="non-HTTPS"):
            download_archive(url, tmp_path / "out.zip")
    assert not (tmp_path / "out.zip").exists()
