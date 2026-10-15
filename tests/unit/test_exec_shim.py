"""Allowlisted r2b-exec harness."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

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
    assert "no-model" in out


def test_forwards_version() -> None:
    code = run_allowlisted(["--version"])
    assert code == 0


def test_preserves_typer_exit_code_for_missing_file() -> None:
    """Regression: missing binary must not report exit 0."""
    code = run_allowlisted(["brief", "/no/such/r2b-missing-bin", "--quick", "--json"])
    assert code == 1


def test_rejects_ask_in_no_model_mode(capsys) -> None:
    code = run_allowlisted(["brief", "/bin/ls", "--quick", "--ask", "--json"])
    assert code == 64
    assert "no-model" in capsys.readouterr().err


def test_rejects_review_mode_llm(capsys) -> None:
    code = run_allowlisted(["review", "brief.json", "--mode", "llm", "--json"])
    assert code == 64
    err = capsys.readouterr().err
    assert "no-model" in err
    assert "--mode" in err


def test_rejects_review_mode_both_equals(capsys) -> None:
    code = run_allowlisted(["review", "brief.json", "--mode=both", "--json"])
    assert code == 64
    assert "no-model" in capsys.readouterr().err


def test_rejects_bundle_review_lens(capsys) -> None:
    code = run_allowlisted(
        ["bundle", "create", "/bin/ls", "--review-lens", "thesis", "--json"]
    )
    assert code == 64
    assert "no-model" in capsys.readouterr().err


def test_allows_review_mode_rules() -> None:
    # Should get past the harness gate; missing file → typer exit 1, not 64.
    code = run_allowlisted(["review", "/no/such/brief.json", "--mode", "rules", "--json"])
    assert code != 64
    assert code in {1, 2}
