"""Optional EMB3D / CWE (and CVE) tags for JSON output and .r2br bundles.

Tags are deterministic metadata supplied by the analyst or a case TAGS file.
Analysis never invents or overwrites them; they are schema-validated and
attached only when the caller asks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

TAGS_SCHEMA_VERSION = "r2b.tags.v1"

_CWE_RE = re.compile(r"\bCWE-(\d{1,5})\b", re.IGNORECASE)
_TID_RE = re.compile(r"\bTID-(\d{1,5})\b", re.IGNORECASE)
_MID_RE = re.compile(r"\bMID-(\d{1,5})\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-(\d{4}-\d{4,7})\b", re.IGNORECASE)
_ID_LIMIT = 32


class TagsError(ValueError):
    """Tags input could not be parsed or failed schema validation."""


@dataclass(frozen=True, slots=True)
class EvidenceTags:
    """Normalized, sorted evidence tags."""

    cwe: tuple[str, ...] = ()
    tid: tuple[str, ...] = ()
    mid: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": TAGS_SCHEMA_VERSION,
            "cwe": list(self.cwe),
            "emb3d": {"tid": list(self.tid), "mid": list(self.mid)},
        }
        if self.cve:
            payload["cve"] = list(self.cve)
        if self.source:
            payload["source"] = self.source
        return payload

    def is_empty(self) -> bool:
        return not (self.cwe or self.tid or self.mid or self.cve)


def normalize_cwe(values: Iterable[str]) -> tuple[str, ...]:
    return _normalize_ids(values, prefix="CWE-", pattern=_CWE_RE, bare_digits=True)


def normalize_tid(values: Iterable[str]) -> tuple[str, ...]:
    return _normalize_ids(values, prefix="TID-", pattern=_TID_RE, bare_digits=True)


def normalize_mid(values: Iterable[str]) -> tuple[str, ...]:
    return _normalize_ids(values, prefix="MID-", pattern=_MID_RE, bare_digits=True)


def normalize_cve(values: Iterable[str]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        text = str(raw or "").strip()
        if not text:
            continue
        match = _CVE_RE.search(text) if not text.upper().startswith("CVE-") else _CVE_RE.fullmatch(text)
        if match is None:
            match = _CVE_RE.search(text)
        if match is None:
            raise TagsError(f"invalid CVE id: {text!r}")
        item = f"CVE-{match.group(1)}"
        if item not in seen:
            seen.add(item)
            out.append(item)
        if len(out) >= _ID_LIMIT:
            break
    return tuple(sorted(out))


def load_tags_file(path: str | Path) -> EvidenceTags:
    """Load tags from a Markdown TAGS.md or a JSON tags document."""

    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TagsError(f"could not read tags file: {exc}") from exc
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TagsError(f"invalid tags JSON: {exc}") from exc
        return tags_from_mapping(payload, source=str(file_path))
    return parse_tags_markdown(text, source=str(file_path))



def _id_sort_key(value: str) -> tuple[str, int]:
    prefix, _, digits = value.partition("-")
    try:
        return (prefix, int(digits))
    except ValueError:
        return (prefix, 0)


def parse_tags_markdown(text: str, *, source: str | None = None) -> EvidenceTags:
    """Extract CWE / TID / MID / CVE ids from lab TAGS.md tables."""

    return EvidenceTags(
        cwe=tuple(sorted({f"CWE-{m}" for m in _CWE_RE.findall(text)}, key=_id_sort_key)),
        tid=tuple(sorted({f"TID-{m}" for m in _TID_RE.findall(text)}, key=_id_sort_key)),
        mid=tuple(sorted({f"MID-{m}" for m in _MID_RE.findall(text)}, key=_id_sort_key)),
        cve=tuple(sorted({f"CVE-{m}" for m in _CVE_RE.findall(text)})),
        source=source,
    )


def tags_from_mapping(payload: Mapping[str, Any], *, source: str | None = None) -> EvidenceTags:
    """Build tags from a dict (CLI JSON or tags.json member)."""

    if payload.get("schema_version") not in {None, TAGS_SCHEMA_VERSION}:
        raise TagsError(f"unsupported tags schema_version: {payload.get('schema_version')!r}")
    emb3d = payload.get("emb3d") or {}
    if emb3d is not None and not isinstance(emb3d, Mapping):
        raise TagsError("emb3d must be an object")
    emb3d = emb3d or {}
    tags = EvidenceTags(
        cwe=normalize_cwe(_as_str_list(payload.get("cwe"), "cwe")),
        tid=normalize_tid(_as_str_list(emb3d.get("tid"), "emb3d.tid")),
        mid=normalize_mid(_as_str_list(emb3d.get("mid"), "emb3d.mid")),
        cve=normalize_cve(_as_str_list(payload.get("cve"), "cve")),
        source=source or (str(payload["source"]) if payload.get("source") else None),
    )
    validate_tags(tags.to_dict())
    return tags


def merge_tags(*parts: EvidenceTags | None) -> EvidenceTags | None:
    """Union several tag sources; later sources win for ``source``."""

    cwe: set[str] = set()
    tid: set[str] = set()
    mid: set[str] = set()
    cve: set[str] = set()
    source: str | None = None
    any_present = False
    for part in parts:
        if part is None or part.is_empty():
            if part is not None and part.source:
                source = part.source
            continue
        any_present = True
        cwe.update(part.cwe)
        tid.update(part.tid)
        mid.update(part.mid)
        cve.update(part.cve)
        if part.source:
            source = part.source
    if not any_present:
        return None
    return EvidenceTags(
        cwe=tuple(sorted(cwe)),
        tid=tuple(sorted(tid)),
        mid=tuple(sorted(mid)),
        cve=tuple(sorted(cve)),
        source=source,
    )


def resolve_tags(
    *,
    tags_file: str | Path | None = None,
    cwe: Iterable[str] | None = None,
    tid: Iterable[str] | None = None,
    mid: Iterable[str] | None = None,
    cve: Iterable[str] | None = None,
) -> EvidenceTags | None:
    """Combine an optional TAGS file with CLI id lists."""

    file_tags = load_tags_file(tags_file) if tags_file else None
    cli_tags = EvidenceTags(
        cwe=normalize_cwe(cwe or ()),
        tid=normalize_tid(tid or ()),
        mid=normalize_mid(mid or ()),
        cve=normalize_cve(cve or ()),
    )
    return merge_tags(file_tags, cli_tags)


def validate_tags(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a canonical tags document."""

    if not isinstance(payload, Mapping):
        raise TagsError("tags must be a JSON object")
    if payload.get("schema_version") != TAGS_SCHEMA_VERSION:
        raise TagsError("tags.schema_version must be r2b.tags.v1")
    emb3d = payload.get("emb3d")
    if not isinstance(emb3d, Mapping):
        raise TagsError("tags.emb3d must be an object")
    for key in ("tid", "mid"):
        if key not in emb3d or not isinstance(emb3d[key], list):
            raise TagsError(f"tags.emb3d.{key} must be an array")
    if "cwe" not in payload or not isinstance(payload["cwe"], list):
        raise TagsError("tags.cwe must be an array")
    if "cve" in payload and not isinstance(payload["cve"], list):
        raise TagsError("tags.cve must be an array")
    if "source" in payload and payload["source"] is not None and not isinstance(payload["source"], str):
        raise TagsError("tags.source must be a string when present")
    # Re-normalize through constructors for canonical form.
    tags = EvidenceTags(
        cwe=normalize_cwe(payload["cwe"]),
        tid=normalize_tid(emb3d["tid"]),
        mid=normalize_mid(emb3d["mid"]),
        cve=normalize_cve(payload.get("cve") or ()),
        source=payload.get("source"),
    )
    return tags.to_dict()


def _normalize_ids(
    values: Iterable[str],
    *,
    prefix: str,
    pattern: re.Pattern[str],
    bare_digits: bool,
) -> tuple[str, ...]:
    out: list[str] = []
    seen_key: set[int] = set()
    for raw in values:
        text = str(raw or "").strip()
        if not text:
            continue
        match = pattern.search(text)
        if match is None and bare_digits and text.isdigit():
            digits = text
        elif match is not None:
            digits = match.group(1)
        else:
            raise TagsError(f"invalid id for {prefix}: {text!r}")
        try:
            key = int(digits)
        except ValueError as exc:
            raise TagsError(f"invalid id for {prefix}: {text!r}") from exc
        if key in seen_key:
            continue
        seen_key.add(key)
        # Preserve zero-padding from the source when present (MID-004, MID-071).
        item = f"{prefix}{digits}"
        out.append(item)
        if len(out) >= _ID_LIMIT:
            break
    return tuple(sorted(out, key=lambda value: int(value.split("-", 1)[1])))


def _as_str_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise TagsError(f"{label} must be an array of strings")
    out: list[str] = []
    for item in value:
        if not isinstance(item, (str, int)):
            raise TagsError(f"{label} entries must be strings")
        out.append(str(item))
    return out


__all__ = [
    "TAGS_SCHEMA_VERSION",
    "EvidenceTags",
    "TagsError",
    "load_tags_file",
    "merge_tags",
    "normalize_cve",
    "normalize_cwe",
    "normalize_mid",
    "normalize_tid",
    "parse_tags_markdown",
    "resolve_tags",
    "tags_from_mapping",
    "validate_tags",
]
