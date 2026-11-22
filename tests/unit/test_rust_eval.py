"""Stripped-Rust CI eval helpers (scripts/rust_eval)."""

import importlib.util
import json
from pathlib import Path

_DIR = Path(__file__).resolve().parents[2] / "scripts" / "rust_eval"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"rust_eval_{name}", _DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


report = _load("report")
truth = _load("truth")


def _row(p5: float, p10: float, error: str | None = None, n_ranked: int = 10) -> dict:
    return {
        "binary": "bins/t/strip/fd",
        "n_funcs": 10,
        "quick": {
            "p@5": p5, "p@10": p10, "error": error, "first_user_rank": 1,
            "user_main_rank": None, "user_total": 2, "n_ranked": n_ranked, "secs": 1.0, "top": [],
        },
    }


BASE = {"bins/t/strip/fd": {"p@5": 0.6, "p@10": 0.3}}


def test_one_lost_hit_is_tolerated():
    assert report.check(_row(0.4, 0.2), BASE["bins/t/strip/fd"]) == []


def test_two_lost_hits_at_k5_fail():
    problems = report.check(_row(0.2, 0.3), BASE["bins/t/strip/fd"])
    assert len(problems) == 1 and problems[0].startswith("p@5")


def test_two_lost_hits_at_k10_fail():
    problems = report.check(_row(0.6, 0.1), BASE["bins/t/strip/fd"])
    assert len(problems) == 1 and problems[0].startswith("p@10")


def test_improvement_and_missing_baseline_pass():
    assert report.check(_row(1.0, 0.8), BASE["bins/t/strip/fd"]) == []
    assert report.check(_row(0.0, 0.0), None) == []


def test_r2b_error_fails_render():
    text, failed = report.render([_row(0.6, 0.3, error="boom")], BASE)
    assert failed and "r2b error" in text
    text, failed = report.render([_row(0.6, 0.3)], BASE)
    assert not failed and "| ok |" in text


def test_checked_in_baseline_names_both_variants():
    baseline = json.loads((_DIR / "baseline.json").read_text())
    for profile in ("strip", "cargostrip"):
        entry = baseline[f"bins/aarch64-unknown-linux-gnu/{profile}/fd"]
        assert set(entry) == {"p@5", "p@10"}


def test_crate_of_attributes_trait_impls_to_the_user_type():
    assert truth.crate_of("fd::walk::scan") == "fd"
    assert truth.crate_of("<fd::cli::Opts as core::fmt::Debug>::fmt") == "fd"
    assert truth.crate_of("<&T as core::fmt::Display>::fmt") == "core"
    assert truth.crate_of("<core::option::Option<T> as fd::Trait>::f") == "fd"
    assert truth.crate_of("OUTLINED_FUNCTION_12") == "llvm_outlined"


def test_short_briefing_counts_missing_ranks_as_misses():
    # The harness divides by the ranked count: one user region scores 1.0/1.0.
    row = _row(1.0, 1.0, n_ranked=1)
    problems = report.check(row, {"p@5": 1.0, "p@10": 0.8})
    assert [p.split()[:2] for p in problems] == [["p@5", "0.20"], ["p@10", "0.10"]]
    text, failed = report.render([row], {"bins/t/strip/fd": {"p@5": 1.0, "p@10": 0.8}})
    assert failed and "| 0.20 | 0.10 |" in text


def test_truth_without_user_functions_fails_loudly():
    recs = [{"name": "_ZN2fd4main17h0123456789abcdefE", "kind": "other"}]
    try:
        truth.require_user(recs, "fd", "sym/fd")
    except SystemExit as exc:
        assert "no `fd` functions" in str(exc) and "1 names still mangled" in str(exc)
    else:
        raise AssertionError("expected SystemExit")
    assert truth.require_user([{"name": "fd::main", "kind": "user"}], "fd", "sym/fd") == 1
