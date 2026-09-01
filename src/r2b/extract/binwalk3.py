"""Binwalk v3 extractor. Scan JSON plus optional ``-e`` into an isolated dir."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
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


def find_binwalk3() -> str | None:
    """Return a Binwalk v3 executable, including Homebrew's ``binwalk`` name.

    Some distributions install v3 as ``binwalk3`` so it can coexist with v2.
    Homebrew exposes the same program as ``binwalk``.  Extraction depends on
    the v3 JSON CLI, so never accept an unversioned v2 binary by accident.
    """
    explicit = shutil.which("binwalk3")
    if explicit:
        return explicit
    candidate = shutil.which("binwalk")
    if not candidate:
        return None
    try:
        output = subprocess.check_output(
            [candidate, "--version"],
            stderr=subprocess.STDOUT,
            timeout=4,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"\bbinwalk\s+v?(\d+)(?:\.\d+)*\b", output, re.IGNORECASE)
    return candidate if match and int(match.group(1)) >= 3 else None


class Binwalk3Extractor:
    name = "binwalk3"

    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or find_binwalk3()

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
        if extract:
            result.notes.extend(_recover_squashfs(subject, output_dir, hits, limits))
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
        extractions = block.get("extractions")
        extraction_map = extractions if isinstance(extractions, dict) else {}
        for item in block.get("file_map") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "unknown")
            offset = int(item.get("offset") or 0)
            extraction = extraction_map.get(str(item.get("id") or ""))
            extraction_d = extraction if isinstance(extraction, dict) else {}
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
                    "extraction_success": extraction_d.get("success"),
                    "extractor": extraction_d.get("extractor"),
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
    """Map Binwalk's hexadecimal ``*.extracted/<offset>/`` directories."""
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
                offset = int(child.name, 16)
            except ValueError:
                continue
            files = [p for p in child.rglob("*") if p.is_file()]
            if files:
                found[offset] = str(files[0])
    return found


def _recover_squashfs(
    subject: Path,
    output_dir: Path,
    hits: list[dict[str, Any]],
    limits: ExtractLimits,
) -> list[str]:
    """Use unsquashfs when Binwalk v3's sasquatch-only extractor fails."""
    unsquashfs = shutil.which("unsquashfs")
    if not unsquashfs:
        return []
    notes: list[str] = []
    subject_size = subject.stat().st_size
    for hit in hits:
        if str(hit.get("name") or "").lower() != "squashfs":
            continue
        extracted = Path(str(hit["extracted_path"])) if hit.get("extracted_path") else None
        if extracted and extracted.exists() and hit.get("extraction_success") is not False:
            continue
        offset = int(hit.get("offset") or 0)
        size = int(hit.get("size") or 0)
        if offset < 0 or offset >= subject_size:
            continue
        size = min(size or subject_size - offset, subject_size - offset)
        if size <= 0:
            continue

        carve = output_dir / f"squashfs-{offset:x}.img"
        fallback_dir = output_dir / f"unsquashfs-{offset:x}"
        rootfs = fallback_dir / "rootfs"
        _copy_range(subject, carve, offset=offset, size=size)
        try:
            recovered = run_sandboxed(
                [unsquashfs, "-force", "-no-progress", "-d", str(rootfs), str(carve)],
                input_file=carve,
                output_dir=fallback_dir,
                limits=limits,
                extra_ro_binds=[Path(unsquashfs)],
            )
        finally:
            carve.unlink(missing_ok=True)
        notes.extend(recovered.notes)
        recovered_files = [path for path in rootfs.rglob("*") if path.is_file()] if rootfs.is_dir() else []
        if recovered_files:
            hit["extracted_path"] = str(rootfs)
            hit["extraction_success"] = True
            hit["extractor"] = "unsquashfs"
            if recovered.returncode == 0:
                notes.append(
                    f"binwalk3 could not unpack squashfs at 0x{offset:x}; unsquashfs recovered the filesystem"
                )
            else:
                notes.append(
                    f"unsquashfs recovered {len(recovered_files)} files at 0x{offset:x} with non-fatal host omissions"
                )
        else:
            detail = recovered.stderr.strip().splitlines()
            suffix = f": {detail[-1]}" if detail else ""
            notes.append(f"unsquashfs fallback failed at 0x{offset:x}{suffix}")
    return notes


def _copy_range(source: Path, destination: Path, *, offset: int, size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    remaining = size
    with source.open("rb") as src, destination.open("wb") as dst:
        src.seek(offset)
        while remaining:
            chunk = src.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)
