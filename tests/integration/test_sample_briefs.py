from __future__ import annotations

import json
from pathlib import Path

import pytest

from r2b import AnalysisOptions, analyze
from r2b.adapters.radare2 import Radare2Adapter


@pytest.mark.integration
@pytest.mark.skipif(not Radare2Adapter().is_available(), reason="radare2 is not installed")
def test_committed_samples_match_first_pass_expectations() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads((root / "samples" / "first-pass-expectations.json").read_text())

    assert manifest["schema_version"] == "r2b.samples.expectations.v1"
    options = AnalysisOptions(profile=manifest["profile"], max_regions=6)
    for case in manifest["cases"]:
        report = analyze(root / case["path"], options=options)
        assert report.subject["subject_class"] == case["subject_class"], case["path"]
        assert report.subject["arch"] == case["arch"], case["path"]
        assert report.subject["dangerous_imports"] == case["dangerous_imports"], case["path"]
        assert [region.id for region in report.regions] == case["region_ids"], case["path"]
        assert report.issues == (), case["path"]
