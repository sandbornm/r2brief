"""Content-addressed artifact DAG.

Extractors (binwalk3, unblob) and in-process inventory (firmware adapter, r2)
normalize into one graph. Nodes for byte-backed objects carry SHA-256.
Functions, imports, strings, and observed endpoints are keyed by parent digest
plus offset. Their labels remain evidence categories, not behavior claims.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..extract.binwalk3 import Binwalk3Extractor
from ..extract.sandbox import ExtractLimits
from ..extract.unblob import UnblobExtractor

DAG_SCHEMA_VERSION = "r2b.artifact_dag.v1"
_LOGGER = logging.getLogger(__name__)

NODE_KINDS = (
    "container",
    "partition",
    "filesystem",
    "file",
    "elf",
    "pe",
    "macho",
    "fat_macho",
    "script",
    "function",
    "import",
    "string",
    "endpoint",
    "config_key",
)

_SIGNAL_KIND = {
    "credential": "string",
    "network": "endpoint",
    "service": "string",
    "crypto": "string",
    "build_path": "string",
    "filesystem": "string",
    "update": "string",
    "dangerous_api": "string",
    "command": "string",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def empty_dag(subject: Path, sha256: str, *, notes: list[str] | None = None) -> dict[str, Any]:
    root_kind = "elf" if _looks_elf(subject) else "file"
    root_id = _node_id(root_kind, sha256)
    return {
        "schema_version": DAG_SCHEMA_VERSION,
        "subject": str(subject),
        "sha256": sha256,
        "generated_at": _utcnow(),
        "tools": [],
        "notes": list(notes or []),
        "nodes": [
            {
                "id": root_id,
                "kind": root_kind,
                "label": subject.name,
                "sha256": sha256,
                "parent_id": None,
                "parent_offset": 0,
                "size": subject.stat().st_size if subject.is_file() else 0,
                "path": str(subject),
                "source_tools": [],
                "confidence": 1.0,
                "properties": {"root": True},
            }
        ],
        "edges": [],
        "summary": {
            "node_count": 1,
            "by_kind": {root_kind: 1},
            "elf_count": 1 if root_kind == "elf" else 0,
        },
    }


def build_artifact_dag(
    subject: Path,
    *,
    firmware: dict[str, Any] | None = None,
    radare2: dict[str, Any] | None = None,
    artifacts_dir: Path | None = None,
    limits: ExtractLimits | None = None,
    run_extractors: bool = True,
    extract_elf: bool = False,
) -> dict[str, Any]:
    """Build a DAG from inventory plus optional sandboxed extractors."""
    subject = subject.resolve()
    digest = firmware.get("sha256") if isinstance(firmware, dict) and firmware.get("sha256") else None
    if not digest:
        digest = sha256_path(subject)
    is_elf = bool(firmware.get("is_elf")) if isinstance(firmware, dict) else _looks_elf(subject)
    executable_format = (
        str(firmware.get("top_level_format") or ("elf" if is_elf else "")).lower()
        if isinstance(firmware, dict)
        else "elf" if is_elf else ""
    )
    is_executable = executable_format in {"elf", "pe", "macho", "fat_macho"}
    root_kind = executable_format if is_executable else "container"
    root_id = _node_id(root_kind, digest)
    builder = _DagBuilder(subject=subject, sha256=digest, root_id=root_id, root_kind=root_kind)

    if isinstance(firmware, dict):
        _ingest_firmware(builder, firmware)
    if isinstance(radare2, dict) and is_executable:
        _ingest_radare2(builder, radare2)

    limits = limits or ExtractLimits()
    should_extract = run_extractors and (extract_elf or not is_executable)
    if should_extract and artifacts_dir is not None:
        scratch = artifacts_dir / "extract" / digest[:2] / digest
        scratch.mkdir(parents=True, exist_ok=True)
        _run_extractors(builder, subject, scratch, limits)

    dag = builder.finish()
    return dag


def compact_dag(dag: dict[str, Any], *, max_nodes: int = 40) -> dict[str, Any]:
    """Briefing-sized view: root + high-value children, not the full tree."""
    nodes = [n for n in dag.get("nodes") or [] if isinstance(n, dict)]
    preferred = {
        "container",
        "partition",
        "filesystem",
        "file",
        "elf",
        "pe",
        "macho",
        "fat_macho",
        "script",
    }
    ranked = sorted(
        nodes,
        key=lambda n: (
            0 if n.get("properties", {}).get("root") else 1,
            0 if n.get("kind") in preferred else 1,
            -(float(n.get("confidence") or 0)),
        ),
    )
    kept = ranked[:max_nodes]
    ids = {n["id"] for n in kept}
    edges = [
        e
        for e in dag.get("edges") or []
        if isinstance(e, dict) and e.get("source") in ids and e.get("target") in ids
    ]
    return {
        "schema_version": DAG_SCHEMA_VERSION,
        "sha256": dag.get("sha256"),
        "tools": dag.get("tools") or [],
        "notes": dag.get("notes") or [],
        "summary": dag.get("summary") or {},
        "nodes": kept,
        "edges": edges,
    }


class _DagBuilder:
    def __init__(self, *, subject: Path, sha256: str, root_id: str, root_kind: str) -> None:
        self.subject = subject
        self.sha256 = sha256
        self.root_id = root_id
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.tools: list[str] = []
        self.notes: list[str] = []
        self.add_node(
            root_id,
            kind=root_kind,
            label=subject.name,
            sha256=sha256,
            parent_id=None,
            parent_offset=0,
            size=subject.stat().st_size if subject.is_file() else 0,
            path=str(subject),
            source_tools=["r2b"],
            confidence=1.0,
            properties={"root": True},
        )

    def add_tool(self, name: str) -> None:
        if name not in self.tools:
            self.tools.append(name)

    def add_node(
        self,
        node_id: str,
        *,
        kind: str,
        label: str,
        sha256: str | None,
        parent_id: str | None,
        parent_offset: int | None,
        size: int | None,
        path: str | None,
        source_tools: Iterable[str],
        confidence: float,
        properties: dict[str, Any] | None = None,
    ) -> str:
        tools = [str(t) for t in source_tools if t]
        existing = self.nodes.get(node_id)
        if existing:
            merged_tools = list(dict.fromkeys([*(existing.get("source_tools") or []), *tools]))
            existing["source_tools"] = merged_tools
            if confidence > float(existing.get("confidence") or 0):
                existing["confidence"] = confidence
            if path and not existing.get("path"):
                existing["path"] = path
            if sha256 and not existing.get("sha256"):
                existing["sha256"] = sha256
            props = dict(existing.get("properties") or {})
            props.update(properties or {})
            existing["properties"] = props
            return node_id
        kind_norm = kind if kind in NODE_KINDS else "file"
        self.nodes[node_id] = {
            "id": node_id,
            "kind": kind_norm,
            "label": label[:200],
            "sha256": sha256,
            "parent_id": parent_id,
            "parent_offset": parent_offset,
            "size": size,
            "path": path,
            "source_tools": tools,
            "confidence": max(0.0, min(1.0, float(confidence))),
            "properties": dict(properties or {}),
        }
        if parent_id:
            self.add_edge("extracted_from", node_id, parent_id, tool=tools[0] if tools else "r2b")
            self.add_edge("contains", parent_id, node_id, tool=tools[0] if tools else "r2b")
        return node_id

    def add_edge(self, kind: str, source: str, target: str, *, tool: str, offset: int | None = None) -> None:
        edge_id = f"e:{kind}:{source}:{target}"
        if edge_id in self.edges:
            return
        self.edges[edge_id] = {
            "id": edge_id,
            "kind": kind,
            "source": source,
            "target": target,
            "source_tool": tool,
            "parent_offset": offset,
        }

    def finish(self) -> dict[str, Any]:
        nodes = list(self.nodes.values())
        by_kind: dict[str, int] = {}
        for node in nodes:
            by_kind[str(node["kind"])] = by_kind.get(str(node["kind"]), 0) + 1
        return {
            "schema_version": DAG_SCHEMA_VERSION,
            "subject": str(self.subject),
            "sha256": self.sha256,
            "generated_at": _utcnow(),
            "tools": list(self.tools),
            "notes": list(self.notes),
            "nodes": nodes,
            "edges": list(self.edges.values()),
            "summary": {
                "node_count": len(nodes),
                "edge_count": len(self.edges),
                "by_kind": by_kind,
                "elf_count": by_kind.get("elf", 0),
            },
        }


def _ingest_firmware(builder: _DagBuilder, firmware: dict[str, Any]) -> None:
    builder.add_tool("firmware")
    for item in firmware.get("embedded_artifacts") or []:
        if not isinstance(item, dict):
            continue
        offset = int(item.get("offset") or 0)
        kind = _firmware_kind(str(item.get("kind") or "file"))
        label = str(item.get("name") or kind)
        sha = item.get("carved_sha256")
        path = item.get("carved_path")
        node_id = _node_id(kind, str(sha) if sha else f"{builder.sha256}:{offset}:{kind}")
        builder.add_node(
            node_id,
            kind=kind,
            label=label,
            sha256=str(sha) if sha else None,
            parent_id=builder.root_id,
            parent_offset=offset,
            size=item.get("carved_size") or item.get("declared_size"),
            path=str(path) if path else None,
            source_tools=[str(item.get("source") or "firmware")],
            confidence=float(item.get("confidence") or 0.7),
            properties={
                "firmware_kind": item.get("kind"),
                "analysis_role": item.get("analysis_role"),
                "description": item.get("description"),
            },
        )
    signals = firmware.get("string_signals") or {}
    if isinstance(signals, dict):
        for signal in (signals.get("top_signals") or [])[:80]:
            if not isinstance(signal, dict):
                continue
            value = str(signal.get("value") or "").strip()
            if not value:
                continue
            category = str(signal.get("category") or "string")
            kind = _SIGNAL_KIND.get(category, "string")
            offset = int(signal.get("offset") or 0)
            node_id = _node_id(kind, f"{builder.sha256}:{offset}:{value[:40]}")
            builder.add_node(
                node_id,
                kind=kind,
                label=value[:120],
                sha256=None,
                parent_id=builder.root_id,
                parent_offset=offset,
                size=len(value),
                path=None,
                source_tools=["firmware"],
                confidence=float(signal.get("confidence") or 0.6),
                properties={"category": category, "label": signal.get("label")},
            )


def _ingest_radare2(builder: _DagBuilder, radare2: dict[str, Any]) -> None:
    builder.add_tool("radare2")
    for func in (radare2.get("functions") or [])[:80]:
        if not isinstance(func, dict):
            continue
        name = str(func.get("name") or "fcn")
        addr = func.get("offset") or func.get("addr") or 0
        try:
            addr_i = int(addr)
        except (TypeError, ValueError):
            addr_i = 0
        node_id = _node_id("function", f"{builder.sha256}:{addr_i}:{name}")
        builder.add_node(
            node_id,
            kind="function",
            label=name,
            sha256=None,
            parent_id=builder.root_id,
            parent_offset=addr_i,
            size=func.get("size"),
            path=None,
            source_tools=["radare2"],
            confidence=0.8,
            properties={"name": name},
        )
    for item in (radare2.get("strings") or [])[:40]:
        if not isinstance(item, dict):
            continue
        text = str(item.get("string") or item.get("value") or "").strip()
        if not text:
            continue
        addr = item.get("vaddr") or item.get("paddr") or 0
        try:
            addr_i = int(addr)
        except (TypeError, ValueError):
            addr_i = 0
        node_id = _node_id("string", f"{builder.sha256}:{addr_i}:{text[:40]}")
        builder.add_node(
            node_id,
            kind="string",
            label=text[:120],
            sha256=None,
            parent_id=builder.root_id,
            parent_offset=addr_i,
            size=len(text),
            path=None,
            source_tools=["radare2"],
            confidence=0.7,
            properties={},
        )
    for item in (radare2.get("imports") or [])[:30]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        node_id = _node_id("import", f"{builder.sha256}:imp:{name}")
        builder.add_node(
            node_id,
            kind="import",
            label=name,
            sha256=None,
            parent_id=builder.root_id,
            parent_offset=0,
            size=None,
            path=None,
            source_tools=["radare2"],
            confidence=0.65,
            properties={"import": True},
        )


def _run_extractors(
    builder: _DagBuilder,
    subject: Path,
    scratch: Path,
    limits: ExtractLimits,
) -> None:
    bw = Binwalk3Extractor()
    if bw.is_available():
        builder.add_tool("binwalk3")
        try:
            result, hits = bw.scan_and_extract(subject, scratch / "binwalk3", limits=limits, extract=True)
            builder.notes.extend(result.notes)
            if result.timed_out:
                builder.notes.append("binwalk3 timed out; DAG includes scan hits only")
            _ingest_extractor_hits(builder, hits, blob_root=scratch / "blobs", max_files=limits.max_files)
        except Exception as exc:
            _LOGGER.debug("binwalk3 extract failed: %s", exc)
            builder.notes.append(f"binwalk3 failed: {exc}")
    else:
        builder.notes.append("binwalk3 not on PATH; skipped")

    ub = UnblobExtractor()
    if ub.is_available():
        builder.add_tool("unblob")
        try:
            result, hits = ub.extract(subject, scratch / "unblob", limits=limits)
            builder.notes.extend(result.notes)
            if result.timed_out:
                builder.notes.append("unblob timed out; DAG includes whatever landed on disk")
            _ingest_extractor_hits(builder, hits, blob_root=scratch / "blobs", max_files=limits.max_files)
        except Exception as exc:
            _LOGGER.debug("unblob extract failed: %s", exc)
            builder.notes.append(f"unblob failed: {exc}")
    else:
        builder.notes.append("unblob not on PATH; skipped")


def _ingest_extractor_hits(
    builder: _DagBuilder,
    hits: list[dict[str, Any]],
    *,
    blob_root: Path,
    max_files: int = 200,
) -> None:
    blob_root.mkdir(parents=True, exist_ok=True)
    for hit in hits[: max(0, max_files)]:
        offset = int(hit.get("offset") or 0)
        kind = str(hit.get("kind") or "file")
        if kind not in NODE_KINDS:
            kind = "file"
        extracted = hit.get("extracted_path")
        sha: str | None = None
        stored: str | None = None
        size = hit.get("size")
        if extracted:
            path = Path(str(extracted))
            if path.is_file():
                try:
                    sha = sha256_path(path)
                    stored = _store_blob(blob_root, sha, path)
                    size = path.stat().st_size
                except OSError:
                    sha = None
        node_id = _node_id(kind, str(sha) if sha else f"{builder.sha256}:{offset}:{hit.get('name')}")
        builder.add_node(
            node_id,
            kind=kind,
            label=str(hit.get("name") or kind),
            sha256=sha,
            parent_id=builder.root_id,
            parent_offset=offset,
            size=size,
            path=stored or (str(extracted) if extracted else None),
            source_tools=[str(hit.get("tool") or "extractor")],
            confidence=float(hit.get("confidence") or 0.7),
            properties={"description": hit.get("description"), "extractor_name": hit.get("name")},
        )


def _store_blob(root: Path, digest: str, src: Path) -> str:
    dest = root / digest[:2] / digest
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        dest.write_bytes(src.read_bytes())
    return str(dest)


def _firmware_kind(kind: str) -> str:
    mapping = {
        "elf_binary": "elf",
        "squashfs_filesystem": "filesystem",
        "cramfs_filesystem": "filesystem",
        "ubi_volume": "filesystem",
        "compressed_stream": "container",
        "archive": "container",
        "uimage": "partition",
        "vendor_wrapper": "container",
        "device_tree": "file",
        "credential_material": "config_key",
    }
    return mapping.get(kind, "file" if kind not in NODE_KINDS else kind)


def _looks_elf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def _node_id(kind: str, key: str) -> str:
    token = hashlib.sha256(f"{kind}:{key}".encode()).hexdigest()[:16]
    return f"n:{kind}:{token}"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def dump_dag(path: Path, dag: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dag, indent=2, sort_keys=False) + "\n", encoding="utf-8")


__all__ = [
    "DAG_SCHEMA_VERSION",
    "NODE_KINDS",
    "build_artifact_dag",
    "compact_dag",
    "dump_dag",
    "empty_dag",
    "sha256_path",
]
