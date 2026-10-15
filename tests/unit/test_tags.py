"""EMB3D / CWE evidence tags."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2b.analysis.tags import (
    TAGS_SCHEMA_VERSION,
    TagsError,
    load_tags_file,
    parse_tags_markdown,
    resolve_tags,
    validate_tags,
)
from r2b.bundle import create_bundle, read_bundle


ASUS_SNIPPET = """
# EMB3D + CWE tags — ASUS

| **CWE-121** | Stack-based Buffer Overflow |
| **CWE-787** | Out-of-bounds Write |
| **TID-327** | Out of Bounds Memory Access |
| **MID-004** | Memory Hardening |
| CVE-2024-3079 | lab id |
"""

TOTOLINK_SNIPPET = """
| **CWE-78** | OS Command Injection |
| **TID-310** | Remotely Accessible Unauthenticated Services |
| MID-071 | Sanitized User Data |
"""


def test_parse_asus_tags_markdown() -> None:
    tags = parse_tags_markdown(ASUS_SNIPPET, source="asus/TAGS.md")
    assert tags.cwe == ("CWE-121", "CWE-787")
    assert tags.tid == ("TID-327",)
    assert "MID-004" in tags.mid
    assert tags.cve == ("CVE-2024-3079",)
    doc = tags.to_dict()
    assert doc["schema_version"] == TAGS_SCHEMA_VERSION
    assert validate_tags(doc)["cwe"] == ["CWE-121", "CWE-787"]


def test_parse_totolink_tags_markdown() -> None:
    tags = parse_tags_markdown(TOTOLINK_SNIPPET)
    assert tags.cwe == ("CWE-78",)
    assert tags.tid == ("TID-310",)
    assert "MID-071" in tags.mid


def test_resolve_tags_merges_file_and_cli(tmp_path: Path) -> None:
    path = tmp_path / "TAGS.md"
    path.write_text(TOTOLINK_SNIPPET, encoding="utf-8")
    tags = resolve_tags(tags_file=path, cwe=["CWE-77"], tid=["TID-310"], mid=["MID-016"])
    assert tags is not None
    assert tags.cwe == ("CWE-77", "CWE-78")
    assert tags.tid == ("TID-310",)
    assert "MID-016" in tags.mid and "MID-071" in tags.mid


def test_load_tags_json(tmp_path: Path) -> None:
    path = tmp_path / "tags.json"
    path.write_text(
        '{"schema_version":"r2b.tags.v1","cwe":["CWE-121"],"emb3d":{"tid":["TID-327"],"mid":[]}}',
        encoding="utf-8",
    )
    tags = load_tags_file(path)
    assert tags.cwe == ("CWE-121",)
    assert tags.tid == ("TID-327",)


def test_invalid_cwe_raises() -> None:
    with pytest.raises(TagsError):
        resolve_tags(cwe=["not-a-cwe"])


def test_bundle_embeds_tags(tmp_path: Path) -> None:
    target = tmp_path / "challenge.bin"
    target.write_bytes(b"\x7fELF\x00tagged")
    briefing = {
        "schema_version": "r2b.briefing.v1",
        "binary": str(target),
        "summary": "s",
        "regions": [],
        "overall_ask": "a",
        "next_steps": [],
        "handoff": {"schema_version": "r2b.handoff.v1", "next_argv": []},
    }
    analysis = {
        "type": "analysis_result",
        "schema_version": "r2b.analysis_result.v1",
        "binary": str(target),
        "tool_status": {},
    }
    tags = resolve_tags(cwe=["CWE-78"], tid=["TID-310"])
    assert tags is not None
    out = tmp_path / "out.r2br"
    bundle = create_bundle(
        out,
        briefing=briefing,
        analysis=analysis,
        tags=tags.to_dict(),
        target=target,
    )
    assert bundle.tags is not None
    assert bundle.tags["cwe"] == ["CWE-78"]
    assert "tags.json" in bundle.summary()["members"]
    reloaded = read_bundle(out)
    assert reloaded.tags == bundle.tags
