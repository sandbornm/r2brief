"""Cortex-M user-main recovery against real rustc / cortex-m-rt firmware.

The images under tests/fixtures/cortex_m/bin are built by
tests/fixtures/cortex_m/build.sh from synthetic sources in that folder.
manifest.json holds each one's user main, read from its symbol twin.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from r2b.analysis.rust import analyze_rust

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "cortex_m"
MANIFEST = json.loads((ROOT / "manifest.json").read_text())["fixtures"]


@pytest.mark.parametrize("name", sorted(MANIFEST))
def test_cortex_fixture_user_main(name: str):
    pytest.importorskip("capstone")
    info = analyze_rust(ROOT / "bin" / name)
    assert info is not None
    assert info["user_main"] == MANIFEST[name]["user_main"], MANIFEST[name]["symbol"]
    assert info["entry_chain"][-1] == info["user_main"]


def test_stripped_fixtures_have_no_symbols():
    from elftools.elf.elffile import ELFFile

    for name in MANIFEST:
        with (ROOT / "bin" / name).open("rb") as fh:
            elf = ELFFile(fh)
            assert elf.get_section_by_name(".symtab") is None, name
            assert elf.get_section_by_name(".comment") is not None, name
