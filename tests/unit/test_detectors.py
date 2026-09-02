"""Unit tests for environment detectors."""

from __future__ import annotations

import shutil
from types import SimpleNamespace

import pytest

from r2b.environment import detectors


def _completed(argv: list[str], stdout: str = "", stderr: str = "", returncode: int = 0):
    return SimpleNamespace(args=argv, stdout=stdout, stderr=stderr, returncode=returncode)


def test_probe_version_skips_radare2_usage_banner(monkeypatch) -> None:
    def fake_run(argv, **_kwargs):
        flag = argv[1]
        if flag == "--version":
            return _completed(
                argv,
                stdout="Usage: r2 [-ACdfjLMnNqStuvwzX] [-P patch] [-p prj] file|pid|-|--|=\n",
            )
        if flag == "-v":
            return _completed(argv, stdout="radare2 6.0.5 0 @ linux-arm-64\nbirth: git.6.0.5\n")
        return _completed(argv, returncode=1)

    monkeypatch.setattr(detectors.subprocess, "run", fake_run)
    assert detectors._probe_version("radare2") == "radare2 6.0.5 0 @ linux-arm-64"


def test_probe_version_uses_first_working_version_flag(monkeypatch) -> None:
    def fake_run(argv, **_kwargs):
        if argv[1] == "--version":
            return _completed(argv, stdout="bubblewrap 0.11.2\n")
        raise AssertionError(f"unexpected flag {argv[1]}")

    monkeypatch.setattr(detectors.subprocess, "run", fake_run)
    assert detectors._probe_version("bwrap") == "bubblewrap 0.11.2"


def test_probe_version_skips_syntax_banner(monkeypatch) -> None:
    def fake_run(argv, **_kwargs):
        flag = argv[1]
        if flag == "--version":
            return _completed(argv, stdout="SYNTAX: sasquatch [OPTIONS] FILESYSTEM\n")
        if flag == "-v":
            return _completed(argv, stdout="unsquashfs version 4.5.1 (2022/03/17)\n")
        return _completed(argv, returncode=1)

    monkeypatch.setattr(detectors.subprocess, "run", fake_run)
    assert detectors._probe_version("sasquatch") == "unsquashfs version 4.5.1 (2022/03/17)"


def test_looks_like_usage() -> None:
    assert detectors._looks_like_usage("Usage: r2 [-ACdf] file")
    assert detectors._looks_like_usage("SYNTAX: sasquatch [OPTIONS] FILESYSTEM")
    assert detectors._looks_like_usage(
        "General Error: Cannot open file --version (CWD: /tmp) : [Errno 2] No such file or directory: '--version'"
    )
    assert not detectors._looks_like_usage("radare2 6.0.5 0 @ linux-arm-64")


@pytest.mark.skipif(shutil.which("radare2") is None, reason="radare2 is not installed")
def test_live_radare2_version_is_not_usage_banner() -> None:
    version = detectors._probe_version("radare2")
    assert version
    assert not version.lower().startswith("usage:")
    assert "radare2" in version.lower() or any(char.isdigit() for char in version)
