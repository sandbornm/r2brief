"""Ground-truth eval helpers."""

from pathlib import Path
import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "eval_ground_truth",
    Path(__file__).resolve().parents[2] / "scripts" / "eval_ground_truth.py",
)
_mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC is not None and _SPEC.loader is not None
_SPEC.loader.exec_module(_mod)


def test_ranked_addrs_skips_bad_decompile_addrs():
    brief = {
        "handoff": {
            "regions": [{"addr": "0x1000"}],
            "decompile_addrs": ["0x2000", "not-a-number", "", None, "0x1000"],
        }
    }
    assert _mod.ranked_addrs(brief) == [0x1000, 0x2000]



def test_precision_at_k_divides_by_available_ranks():
    recs = [{"addr": 0x1000, "size": 16, "name": "c::main", "kind": "user"}]
    result = _mod.metrics([0x1000], recs, "c")
    assert result["p@1"] == 1.0
    assert result["p@3"] == 1.0
    assert result["p@5"] == 1.0
    empty = _mod.metrics([], recs, "c")
    assert empty["p@1"] == 0.0


def test_main_nonzero_when_r2b_emits_no_json(tmp_path: Path):
    data = tmp_path / "data"
    truth = data / "dataset" / "truth" / "tgt" / "rel"
    truth.mkdir(parents=True)
    (truth / "crate.jsonl").write_text(
        '{"addr": 4096, "size": 16, "name": "crate::main", "kind": "user"}\n',
        encoding="utf-8",
    )
    bins = data / "out" / "bins" / "tgt" / "rel"
    bins.mkdir(parents=True)
    (bins / "crate").write_bytes(b"\x7fELF")
    r2b = tmp_path / "fake-r2b"
    r2b.write_text("#!/bin/sh\necho not-json\n", encoding="utf-8")
    r2b.chmod(0o755)
    rc = _mod.main(
        [
            "--data-root",
            str(data),
            "--r2b",
            str(r2b),
            "--modes",
            "quick",
            "out/bins/tgt/rel/crate",
        ]
    )
    assert rc != 0
