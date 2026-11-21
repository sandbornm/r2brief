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
