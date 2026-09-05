"""Unblob extractor. Optional; skipped when the CLI is missing."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .sandbox import ExtractLimits, SandboxResult, run_sandboxed


class UnblobExtractor:
    name = "unblob"

    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or shutil.which("unblob")

    def is_available(self) -> bool:
        return bool(self.binary)

    def extract(
        self,
        subject: Path,
        output_dir: Path,
        *,
        limits: ExtractLimits | None = None,
    ) -> tuple[SandboxResult, list[dict[str, Any]]]:
        if not self.binary:
            raise FileNotFoundError("unblob is not on PATH")
        limits = limits or ExtractLimits()
        extract_dir = output_dir / "unblob"
        extract_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "unblob-report.json"
        argv = [
            self.binary,
            "--extract-dir",
            str(extract_dir),
            "--depth",
            str(max(1, limits.max_depth)),
            "--report",
            str(report_path),
            "--process-num",
            "1",
            str(subject.resolve()),
        ]
        result = run_sandboxed(
            argv,
            input_file=subject,
            output_dir=output_dir,
            limits=limits,
            extra_ro_binds=[Path(self.binary)],
        )
        if result.returncode:
            result.notes.append(f"unblob exited {result.returncode}: {result.stderr[-1000:].strip()}")
        hits = _parse_report(report_path, subject=subject)
        # Chunk reports do not carry extracted paths. Keep the actual files too.
        known_paths = {hit.get("extracted_path") for hit in hits}
        hits.extend(hit for hit in _walk_tree(extract_dir)
                    if hit.get("extracted_path") not in known_paths)
        return result, hits


def _parse_report(path: Path, *, subject: Path | None = None) -> list[dict[str, Any]]:
    if not path.is_file():
        # unblob sometimes writes next to the extract dir.
        sibling = path.parent / "unblob" / "unblob.json"
        path = sibling if sibling.is_file() else path
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows: list[dict[str, Any]] = []
    if not isinstance(payload, (dict, list)):
        return []
    nodes = payload if isinstance(payload, list) else payload.get("reports") or payload.get("files") or []
    if isinstance(payload, dict) and not nodes:
        nodes = [payload]
    # Modern unblob emits TaskResult[] with nested ChunkReports. Their offsets
    # are relative to each task's input, so only root chunks belong on this DAG.
    if isinstance(nodes, list) and any(isinstance(node, dict) and "task" in node for node in nodes):
        chunks = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            task = node.get("task") or {}
            if subject is not None and task.get("path") != str(subject.resolve()):
                continue
            for report in node.get("reports") or []:
                if isinstance(report, dict) and report.get("__typename__") in {"ChunkReport", "UnknownChunkReport"}:
                    chunks.append(report)
            if subject is None:
                break
        nodes = chunks
    for item in nodes:
        if not isinstance(item, dict):
            continue
        offset = item.get("start_offset", item.get("offset", 0))
        try:
            offset_i = int(offset or 0)
        except (TypeError, ValueError):
            offset_i = 0
        path_text = str(item.get("path") or item.get("extracted_path") or "")
        name = str(item.get("handler_name") or item.get("handler") or item.get("name") or Path(path_text).name or "unblob")
        try:
            size = max(0, int(item.get("size") or int(item.get("end_offset") or 0) - offset_i))
        except (TypeError, ValueError):
            size = 0
        rows.append(
            {
                "tool": "unblob",
                "offset": offset_i,
                "size": size,
                "name": name,
                "kind": _kind_from_unblob(item, name),
                "confidence": 0.85,
                "description": str(item.get("description") or name),
                "extracted_path": path_text or None,
            }
        )
    return rows


def _walk_tree(extract_dir: Path) -> list[dict[str, Any]]:
    if not extract_dir.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(extract_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith("."):
            continue
        rel = path.relative_to(extract_dir)
        rows.append(
            {
                "tool": "unblob",
                "offset": 0,
                "size": path.stat().st_size,
                "name": path.name,
                "kind": _kind_from_filename(path),
                "confidence": 0.6,
                "description": str(rel),
                "extracted_path": str(path),
            }
        )
        if len(rows) >= 200:
            break
    return rows


def _kind_from_unblob(item: dict[str, Any], name: str) -> str:
    hint = str(item.get("kind") or item.get("type") or name).lower()
    if "elf" in hint:
        return "elf"
    if any(token in hint for token in ("squash", "ubifs", "jffs", "ext", "cramfs")):
        return "filesystem"
    if any(token in hint for token in ("partition", "gpt", "uimage")):
        return "partition"
    if any(token in hint for token in ("zip", "tar", "gzip", "xz", "lzma")):
        return "container"
    if hint.endswith((".sh", ".ash", "script")):
        return "script"
    return "file"


def _kind_from_filename(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".elf") or path.read_bytes()[:4] == b"\x7fELF":
        return "elf"
    if name.endswith((".sh", ".ash")):
        return "script"
    if name.endswith((".squashfs", ".ubifs")):
        return "filesystem"
    return "file"
