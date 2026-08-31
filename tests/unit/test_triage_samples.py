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
