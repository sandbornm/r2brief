from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


def _load_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "corpus_intake.py"
    spec = importlib.util.spec_from_file_location("corpus_intake", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus_intake = _load_module()


def test_shipped_manifest_is_valid_and_pinned() -> None:
    payload = corpus_intake.load_manifest(corpus_intake.DEFAULT_MANIFEST)
    by_id = {item["id"]: item for item in payload["datasets"]}

    assert by_id["nist-juliet-c-cpp-1.3"]["sha256"] == (
        "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
    )
    assert len(by_id["darpa-cgc-multios"]["commit"]) == 40
    assert {
        "openwrt-bpi-r3-mini-24.10.3",
        "openwrt-bpi-r3-mini-24.10.4",
    }.issubset(by_id)


@pytest.mark.parametrize(
    "url",
    [
        "http://samate.nist.gov/archive.zip",
        "https://user:password@samate.nist.gov/archive.zip",
        "https://example.invalid/archive.zip",
    ],
)
def test_url_guard_rejects_insecure_or_unlisted_sources(url: str) -> None:
    with pytest.raises(corpus_intake.IntakeError):
        corpus_intake._validate_url(url, {"samate.nist.gov"})


def test_manifest_rejects_traversal_filename(tmp_path: Path) -> None:
    payload = {
        "schema_version": "r2b.corpus-manifest.v1",
        "allowed_hosts": ["samate.nist.gov"],
        "datasets": [{
            "id": "bad-file",
            "kind": "https",
            "filename": "../escape.zip",
            "url": "https://samate.nist.gov/archive.zip",
            "sha256": "a" * 64,
            "max_bytes": 100,
        }],
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(corpus_intake.IntakeError, match="unsafe filename"):
        corpus_intake.load_manifest(manifest)


def test_list_never_creates_output(tmp_path: Path, capsys) -> None:
    output = tmp_path / "corpus"

    result = corpus_intake.main(["--output", str(output), "list"])

    assert result == 0
    assert not output.exists()
    assert "nist-juliet-c-cpp-1.3" in capsys.readouterr().out
