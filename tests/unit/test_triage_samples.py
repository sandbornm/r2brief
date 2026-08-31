from __future__ import annotations

import json
from pathlib import Path


def test_shallow_triage_fixture_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    sample_dir = root / "samples" / "triage"
    source = (sample_dir / "shallow.c").read_text()
    manifest = json.loads((sample_dir / "manifest.json").read_text())

    assert manifest["schema_version"] == "r2b.samples.v1"
    assert {target["format"] for target in manifest["targets"]} >= {"elf", "pe", "native"}
    for signal in manifest["expected"]["strings"]:
        assert signal in source
    for symbol in manifest["expected"]["imports_any"]:
        assert symbol in source
    assert "system(" not in source
    assert "exec(" not in source


def test_first_pass_expectations_cover_every_committed_sample() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads((root / "samples" / "first-pass-expectations.json").read_text())
    cases = manifest["cases"]

    assert manifest["schema_version"] == "r2b.samples.expectations.v1"
    assert manifest["profile"] == "triage"
    assert {case["path"] for case in cases} == {
        str(path.relative_to(root))
        for path in (root / "samples" / "bin").glob("**/*")
        if path.is_file() and path.name != "manifest.json"
    } | {
        str(path.relative_to(root))
        for path in (root / "samples" / "triage" / "bin").glob("*")
        if path.is_file()
    }
    for case in cases:
        assert (root / case["path"]).is_file()
        assert case["region_ids"]
        assert case["purpose"]
