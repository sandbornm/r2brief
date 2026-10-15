"""Allowlisted r2b-exec harness."""

from __future__ import annotations

from r2b.harness.exec_shim import ALLOWED_SUBCOMMANDS, run_allowlisted


def test_allowlist_includes_core_verbs() -> None:
    for name in ("brief", "verify", "diff", "bundle", "env"):
        assert name in ALLOWED_SUBCOMMANDS


def test_denied_subcommand(capsys) -> None:
    code = run_allowlisted(["rm", "-rf", "/"])
    assert code == 64
    err = capsys.readouterr().err
    assert "not allowlisted" in err


def test_help_lists_allowed(capsys) -> None:
    code = run_allowlisted(["--help"])
    assert code == 0
    out = capsys.readouterr().out
    assert "brief" in out
    assert "verify" in out


def test_forwards_version() -> None:
    code = run_allowlisted(["--version"])
    assert code == 0
