"""Binwalk v3 extractor. Scan JSON plus optional ``-e`` into an isolated dir."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .sandbox import ExtractLimits, SandboxResult, run_sandboxed


_KIND_BY_NAME = {
    "gzip": "container",
    "xz": "container",
    "lzma": "container",
    "bzip2": "container",
    "zstd": "container",
    "zip": "container",
    "tar": "container",
    "cpio": "container",
    "squashfs": "filesystem",
    "cramfs": "filesystem",
    "jffs2": "filesystem",
    "ubifs": "filesystem",
    "ext": "filesystem",
    "ext2": "filesystem",
    "ext3": "filesystem",
    "ext4": "filesystem",
    "fat": "filesystem",
    "ntfs": "filesystem",
    "uimage": "partition",
    "gpt": "partition",
    "mbr": "partition",
    "efi": "partition",
    "elf": "elf",
}


class Binwalk3Extractor:
    name = "binwalk3"

    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or shutil.which("binwalk3")

    def is_available(self) -> bool:
        return bool(self.binary)

    def scan_and_extract(
        self,
        subject: Path,
        output_dir: Path,
        *,
        limits: ExtractLimits | None = None,
        extract: bool = True,
    ) -> tuple[SandboxResult, list[dict[str, Any]]]:
        if not self.binary:
            raise FileNotFoundError("binwalk3 is not on PATH")
        limits = limits or ExtractLimits()
        log_path = output_dir / "binwalk3.json"
        argv = [self.binary, "-l", str(log_path)]
        if extract:
            argv.extend(["-e", "-C", str(output_dir)])
        argv.append(str(subject.resolve()))
        result = run_sandboxed(
            argv,
            input_file=subject,
            output_dir=output_dir,
            limits=limits,
            extra_ro_binds=[Path(self.binary)],
        )
        hits = _parse_log(log_path)
        extracted = _index_extracted(output_dir)
        for hit in hits:
            hit["extracted_path"] = extracted.get(int(hit.get("offset") or -1))
        return result, hits


def kind_for_name(name: str) -> str:
    key = name.strip().lower()
    if key in _KIND_BY_NAME:
        return _KIND_BY_NAME[key]
    for prefix, kind in _KIND_BY_NAME.items():
        if key.startswith(prefix):
            return kind
    return "file"


def _parse_log(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows: list[dict[str, Any]] = []
    analyses = payload if isinstance(payload, list) else [payload]
    for analysis in analyses:
        if not isinstance(analysis, dict):
            continue
        block = analysis.get("Analysis") if "Analysis" in analysis else analysis
        if not isinstance(block, dict):
            continue
        for item in block.get("file_map") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "unknown")
            offset = int(item.get("offset") or 0)
            rows.append(
                {
                    "tool": "binwalk3",
                    "offset": offset,
                    "size": int(item.get("size") or 0),
                    "name": name,
                    "kind": kind_for_name(name),
                    "confidence": _confidence(item.get("confidence")),
                    "description": str(item.get("description") or ""),
                    "extraction_declined": bool(item.get("extraction_declined")),
                }
            )
    return rows


def _confidence(raw: Any) -> float:
    if isinstance(raw, bool):
        return 0.9 if raw else 0.4
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.5
    if value > 1.0:
        return min(1.0, value / 250.0)
    return max(0.0, min(1.0, value))


def _index_extracted(output_dir: Path) -> dict[int, str]:
    """Map binwalk3 ``<name>.extracted/<offset>/...`` trees back to offsets."""
    found: dict[int, str] = {}
    if not output_dir.is_dir():
        return found
    for extracted_root in output_dir.rglob("*.extracted"):
        if not extracted_root.is_dir():
            continue
        for child in extracted_root.iterdir():
            if not child.is_dir():
                continue
            try:
                offset = int(child.name, 0)
            except ValueError:
                continue
            files = [p for p in child.rglob("*") if p.is_file()]
            if files:
                found[offset] = str(files[0])
    return found
