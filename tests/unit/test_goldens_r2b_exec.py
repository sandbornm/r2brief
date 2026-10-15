"""Deterministic r2b-exec checks against tests/goldens (no model)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from r2b.harness.exec_shim import run_allowlisted

GOLDENS = Path(__file__).resolve().parents[1] / "goldens"
HAVE_R2 = shutil.which("radare2") is not None


def _load(name: str) -> tuple[Path, dict]:
    root = GOLDENS / name
    expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
    return root, expected


def _run(argv: list[str], cwd: Path) -> tuple[int, str, str]:
    import os
    import sys
    from io import StringIO

    old = os.getcwd()
    os.chdir(cwd)
    try:
        buf_out, buf_err = StringIO(), StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = buf_out, buf_err
        try:
            code = run_allowlisted(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, buf_out.getvalue(), buf_err.getvalue()
    finally:
        os.chdir(old)


def _check_tags(actual: dict, expect: dict) -> None:
    assert actual.get("schema_version") == expect.get("schema_version", "r2b.tags.v1")
    for key, contains in (
        ("cwe", "cwe_contains"),
        ("cve", "cve_contains"),
    ):
        if contains in expect:
            have = set(actual.get(key) or [])
            assert set(expect[contains]) <= have
    if "cwe" in expect and "cwe_contains" not in expect:
        assert actual.get("cwe") == expect["cwe"]
    emb = actual.get("emb3d") or {}
    if "emb3d" in expect and "tid_contains" not in expect and "mid_contains" not in expect:
        assert emb.get("tid") == expect["emb3d"].get("tid")
        assert emb.get("mid") == expect["emb3d"].get("mid")
    if "tid_contains" in expect:
        assert set(expect["tid_contains"]) <= set(emb.get("tid") or [])
    if "mid_contains" in expect:
        assert set(expect["mid_contains"]) <= set(emb.get("mid") or [])


def _check_payload(payload: dict, expect: dict) -> None:
    if "schema_version" in expect:
        assert payload.get("schema_version") == expect["schema_version"]
    if expect.get("require_handoff"):
        assert isinstance(payload.get("handoff"), dict)
    if "reduction" in expect:
        red = payload.get("reduction") or {}
        for key, value in expect["reduction"].items():
            assert red.get(key) == value, (key, red.get(key), value)
    if "changed_elf_relpaths" in expect:
        got = sorted(item["relpath"] for item in payload.get("changed_elfs") or [])
        assert got == expect["changed_elf_relpaths"]
    if "tags" in expect:
        assert "tags" in payload
        _check_tags(payload["tags"], expect["tags"])
    for key in expect.get("expect_keys") or []:
        assert key in payload


@pytest.mark.parametrize("name", ["hello", "openwrt_ubusd", "asus_cve_2024_3079", "totolink_cwe78"])
def test_golden_r2b_exec_commands(name: str, tmp_path: Path) -> None:
    root, expected = _load(name)
    for cmd in expected.get("commands") or []:
        argv = list(cmd["argv"])
        if cmd.get("optional_if_no_r2") and not HAVE_R2:
            # Skip only this command when radare2 is required; keep exit/no-model checks.
            if argv and argv[0] in {"brief", "verify", "bundle"}:
                continue
        code, out, err = _run(argv, root)
        assert code == cmd["exit_code"], (argv, code, out[:400], err[:400])
        if "expect_stderr_contains" in cmd:
            assert cmd["expect_stderr_contains"] in err
        if code != 0:
            continue
        if "expect_keys" in cmd and cmd.get("argv", [None])[0] == "env":
            payload = json.loads(out[out.find("{") :])
            _check_payload(payload, {"expect_keys": cmd["expect_keys"]})
            continue
        if "expect" in cmd:
            start = out.find("{")
            assert start >= 0, out[:400]
            payload = json.loads(out[start:])
            _check_payload(payload, cmd["expect"])


def test_openwrt_ubusd_diff_reduction() -> None:
    root, expected = _load("openwrt_ubusd")
    cmd = expected["commands"][0]
    code, out, err = _run(list(cmd["argv"]), root)
    assert code == 0, err
    payload = json.loads(out[out.find("{") :])
    _check_payload(payload, cmd["expect"])


def test_hello_bundle_hash_stable(tmp_path: Path) -> None:
    root, expected = _load("hello")
    spec = expected.get("bundle_stability")
    if not spec:
        pytest.skip("no bundle_stability")
    if spec.get("optional_if_no_r2") and not HAVE_R2:
        pytest.skip("radare2 not installed")
    hashes = []
    for i in range(2):
        out_path = tmp_path / f"hello-{i}.r2br"
        argv = [x if x != "OUT" else str(out_path) for x in spec["argv_template"]]
        code, out, err = _run(argv, root)
        assert code == 0, err
        # Prefer hashing the file bytes for stability.
        import hashlib

        hashes.append(hashlib.sha256(out_path.read_bytes()).hexdigest())
    assert hashes[0] == hashes[1]


def test_no_model_rejects_across_goldens() -> None:
    root, expected = _load("openwrt_ubusd")
    for cmd in expected.get("no_model_rejects") or []:
        code, _out, err = _run(list(cmd["argv"]), root)
        assert code == cmd["exit_code"]
        assert "no-model" in err or code == 64


def test_golden_tags_files_parse() -> None:
    from r2b.analysis.tags import load_tags_file

    asus = load_tags_file(GOLDENS / "asus_cve_2024_3079" / "TAGS.md")
    assert "CWE-121" in asus.cwe and "TID-327" in asus.tid
    tot = load_tags_file(GOLDENS / "totolink_cwe78" / "TAGS.md")
    assert "CWE-78" in tot.cwe and "TID-310" in tot.tid
