from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from r2b.analysis.artifact_dag import (
    DAG_SCHEMA_VERSION,
    NODE_KINDS,
    build_artifact_dag,
    compact_dag,
    empty_dag,
)
from r2b.extract.binwalk3 import _index_extracted, _parse_log, find_binwalk3, kind_for_name


def test_kind_for_name_maps_binwalk3_hits() -> None:
    assert kind_for_name("squashfs") == "filesystem"
    assert kind_for_name("gzip") == "container"
    assert kind_for_name("elf") == "elf"
    assert kind_for_name("unknown-blob") == "file"


def test_parse_binwalk3_log(tmp_path: Path) -> None:
    log = tmp_path / "binwalk3.json"
    log.write_text(
        json.dumps(
            [
                {
                    "Analysis": {
                        "file_path": "/tmp/x.gz",
                        "file_map": [
                            {
                                "id": "gzip-1",
                                "offset": 0,
                                "size": 31,
                                "name": "gzip",
                                "confidence": 250,
                                "description": "gzip compressed data",
                                "extraction_declined": False,
                            }
                        ],
                        "extractions": {
                            "gzip-1": {
                                "success": True,
                                "extractor": "gzip_built_in",
                            }
                        },
                    }
                }
            ]
        ),
        encoding="utf-8",
    )
    hits = _parse_log(log)
    assert len(hits) == 1
    assert hits[0]["kind"] == "container"
    assert hits[0]["offset"] == 0
    assert hits[0]["confidence"] == 1.0
    assert hits[0]["extraction_success"] is True
    assert hits[0]["extractor"] == "gzip_built_in"


def test_find_binwalk3_accepts_homebrew_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_which(name: str) -> str | None:
        return "/opt/homebrew/bin/binwalk" if name == "binwalk" else None

    monkeypatch.setattr("r2b.extract.binwalk3.shutil.which", fake_which)
    monkeypatch.setattr(
        "r2b.extract.binwalk3.subprocess.check_output",
        lambda *args, **kwargs: "binwalk 3.1.0\n",
    )

    assert find_binwalk3() == "/opt/homebrew/bin/binwalk"


def test_find_binwalk3_rejects_v2_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_which(name: str) -> str | None:
        return "/usr/bin/binwalk" if name == "binwalk" else None

    monkeypatch.setattr("r2b.extract.binwalk3.shutil.which", fake_which)
    monkeypatch.setattr(
        "r2b.extract.binwalk3.subprocess.check_output",
        lambda *args, **kwargs: "Binwalk v2.3.4\n",
    )

    assert find_binwalk3() is None


def test_index_extracted_reads_binwalk_hex_offsets(tmp_path: Path) -> None:
    extracted = tmp_path / "firmware.bin.extracted" / "1000"
    extracted.mkdir(parents=True)
    child = extracted / "decompressed.bin"
    child.write_bytes(b"payload")

    indexed = _index_extracted(tmp_path)

    assert indexed[0x1000] == str(child)


def test_dag_from_firmware_inventory(tmp_path: Path) -> None:
    blob = tmp_path / "wrapper.bin"
    blob.write_bytes(b"fw-type:Cloud" + b"\x00" * 64 + b"\x7fELF" + b"\x00" * 16)
    firmware = {
        "sha256": "a" * 64,
        "is_elf": False,
        "embedded_artifacts": [
            {
                "offset": 0,
                "kind": "vendor_wrapper",
                "name": "TP-Link Cloud",
                "source": "signature",
                "confidence": 0.9,
                "analysis_role": "container",
            },
            {
                "offset": 77,
                "kind": "elf_binary",
                "name": "ELF",
                "source": "signature",
                "confidence": 0.95,
                "carved_sha256": "b" * 64,
                "carved_path": str(tmp_path / "child.elf"),
                "carved_size": 20,
                "analysis_role": "code",
            },
        ],
        "string_signals": {
            "top_signals": [
                {
                    "category": "network",
                    "value": "http://tplinkdeco.net",
                    "offset": 12,
                    "confidence": 0.8,
                    "label": "endpoint",
                }
            ]
        },
    }
    dag = build_artifact_dag(
        blob,
        firmware=firmware,
        run_extractors=False,
    )
    assert dag["schema_version"] == DAG_SCHEMA_VERSION
    kinds = {n["kind"] for n in dag["nodes"]}
    assert "container" in kinds
    assert "elf" in kinds
    assert "endpoint" in kinds
    credential = next(n for n in dag["nodes"] if n["label"] == "http://tplinkdeco.net")
    assert credential["kind"] == "endpoint"
    elf = next(n for n in dag["nodes"] if n["kind"] == "elf")
    assert elf["parent_offset"] == 77
    assert elf["sha256"] == "b" * 64
    assert "firmware" in elf["source_tools"] or "signature" in elf["source_tools"]
    compact = compact_dag(dag)
    assert compact["schema_version"] == DAG_SCHEMA_VERSION
    assert compact["nodes"]


def test_dag_elf_functions_and_imports(tmp_path: Path) -> None:
    elf = tmp_path / "prog.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
    dag = build_artifact_dag(
        elf,
        firmware={"sha256": "c" * 64, "is_elf": True},
        radare2={
            "functions": [{"name": "main", "offset": 0x7A8, "size": 40}],
            "imports": [{"name": "system"}],
            "strings": [{"string": "/etc/passwd", "vaddr": 0x2000}],
        },
        run_extractors=False,
    )
    kinds = {n["kind"] for n in dag["nodes"]}
    assert kinds >= {"elf", "function", "import", "string"}
    imported = next(n for n in dag["nodes"] if n["label"] == "system")
    assert imported["kind"] == "import"
    assert all(n["kind"] in NODE_KINDS for n in dag["nodes"])


def test_empty_dag_kind_matches_bytes(tmp_path: Path) -> None:
    blob = tmp_path / "plain.bin"
    blob.write_bytes(b"not-elf")
    dag = empty_dag(blob, "d" * 64)
    assert dag["nodes"][0]["kind"] == "file"
    assert dag["nodes"][0]["id"].startswith("n:file:")

    elf = tmp_path / "prog.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 8)
    elf_dag = empty_dag(elf, "e" * 64)
    assert elf_dag["nodes"][0]["kind"] == "elf"
    assert elf_dag["summary"]["elf_count"] == 1


def test_gzip_extract_with_binwalk3_if_present(tmp_path: Path) -> None:
    if not find_binwalk3():
        pytest.skip("binwalk3 not on PATH")
    payload = gzip.compress(b"hello-from-dag")
    gz = tmp_path / "tiny.gz"
    gz.write_bytes(payload)
    dag = build_artifact_dag(
        gz,
        firmware={"sha256": None, "is_elf": False},
        artifacts_dir=tmp_path / "art",
        run_extractors=True,
    )
    tools = dag.get("tools") or []
    assert "binwalk3" in tools
    kinds = {n["kind"] for n in dag["nodes"]}
    assert "container" in kinds or "file" in kinds
