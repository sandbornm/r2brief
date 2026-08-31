"""Portable, content-addressed r2b evidence bundles.

The container is deliberately boring: a deterministic ZIP with a small,
versioned manifest and canonical JSON members.  The analyzed target is
identified by SHA-256 but is not copied into the bundle unless the caller
explicitly opts in.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from . import __version__

BUNDLE_SCHEMA_VERSION = "r2b.bundle.v1"
BUNDLE_EXTENSION = ".r2br"
BUNDLE_MEDIA_TYPE = "application/vnd.r2brief.bundle+zip"

_MIMETYPE_MEMBER = "mimetype"
_MANIFEST_MEMBER = "manifest.json"
_BRIEFING_MEMBER = "briefing.json"
_ANALYSIS_MEMBER = "analysis.json"
_TOOLS_MEMBER = "tools.json"
_PROVENANCE_MEMBER = "provenance.json"
_REVIEW_MEMBER = "review.json"
_TARGET_MEMBER = "target.bin"
_ALLOWED_MEMBERS = frozenset(
    {
        _MIMETYPE_MEMBER,
        _MANIFEST_MEMBER,
        _BRIEFING_MEMBER,
        _ANALYSIS_MEMBER,
        _TOOLS_MEMBER,
        _PROVENANCE_MEMBER,
        _REVIEW_MEMBER,
        _TARGET_MEMBER,
    }
)
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_MAX_MEMBERS = 8
_MAX_MANIFEST_BYTES = 1 * 1024 * 1024
_MAX_JSON_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_TARGET_MEMBER_BYTES = 512 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024


class BundleError(ValueError):
    """The bundle could not be created or failed validation."""


@dataclass(frozen=True, slots=True)
class BundleContents:
    """Validated metadata and evidence documents from a bundle.

    Target bytes are intentionally not loaded into memory.  Consumers that
    need them can inspect ``manifest["subject"]["member"]`` and make a
    separate, explicit extraction decision.
    """

    path: Path
    sha256: str
    manifest: dict[str, Any]
    briefing: dict[str, Any]
    analysis: dict[str, Any]
    tool_status: dict[str, Any]
    provenance: dict[str, Any] | None
    review: dict[str, Any] | None

    def summary(self) -> dict[str, Any]:
        subject = _object(self.manifest.get("subject"), "manifest.subject")
        entries_value = self.manifest.get("entries")
        entries = entries_value if isinstance(entries_value, list) else []
        return {
            "schema_version": self.manifest["schema_version"],
            "path": str(self.path),
            "bundle_sha256": self.sha256,
            "subject": subject,
            "target_included": bool(subject.get("bytes_included")),
            "members": [entry["path"] for entry in entries if isinstance(entry, dict)],
        }


def create_bundle(
    destination: str | Path,
    *,
    briefing: Mapping[str, Any],
    analysis: Mapping[str, Any],
    tool_status: Mapping[str, Any] | None = None,
    review: Mapping[str, Any] | None = None,
    target: str | Path | None = None,
    include_target: bool = False,
) -> BundleContents:
    """Write and validate a deterministic evidence bundle.

    ``target`` is hashed when supplied, even when ``include_target`` is false.
    This content address lets a recipient match the evidence to bytes already
    in their custody without redistributing the target.
    """

    output = Path(destination)
    if output.exists() and output.is_dir():
        raise BundleError(f"bundle destination is a directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    briefing_doc = _json_object(briefing, "briefing")
    analysis_doc = _json_object(analysis, "analysis")
    tools_doc = _json_object(
        tool_status if tool_status is not None else analysis_doc.get("tool_status", {}),
        "tool_status",
    )
    if briefing_doc.get("schema_version") != "r2b.briefing.v1":
        raise BundleError("briefing must use schema_version r2b.briefing.v1")

    target_path = Path(target) if target is not None else None
    if include_target and target_path is None:
        raise BundleError("include_target=True requires a target path")
    subject = _subject_descriptor(target_path, briefing_doc)

    documents = {
        _ANALYSIS_MEMBER: _canonical_json(analysis_doc),
        _BRIEFING_MEMBER: _canonical_json(briefing_doc),
        _TOOLS_MEMBER: _canonical_json(tools_doc),
    }
    if review is not None:
        review_doc = _json_object(review, "review")
        if review_doc.get("schema_version") not in {"r2b.review.v1", "r2b.review-set.v1"}:
            raise BundleError("review must use schema_version r2b.review.v1 or r2b.review-set.v1")
        documents[_REVIEW_MEMBER] = _canonical_json(review_doc)
    provenance = analysis_doc.get("provenance")
    if provenance is not None:
        documents[_PROVENANCE_MEMBER] = _canonical_json(_json_object(provenance, "provenance"))
    entries = [_entry_descriptor(name, payload, _role_for(name)) for name, payload in documents.items()]
    if include_target and target_path is not None:
        entries.append(
            {
                "path": _TARGET_MEMBER,
                "role": "target",
                "media_type": "application/octet-stream",
                "sha256": subject["sha256"],
                "size": subject["size"],
            }
        )
        subject["bytes_included"] = True
        subject["member"] = _TARGET_MEMBER

    manifest: dict[str, Any] = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "container": "zip",
        "producer": {"name": "r2b", "version": __version__},
        "subject": subject,
        "entries": sorted(entries, key=lambda entry: str(entry["path"])),
    }
    handoff = briefing_doc.get("handoff")
    if isinstance(handoff, dict) and "requires_scope" in handoff:
        manifest["requires_scope"] = bool(handoff["requires_scope"])
    manifest_bytes = _canonical_json(manifest)

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            _write_mimetype(archive)
            _write_bytes(archive, _MANIFEST_MEMBER, manifest_bytes)
            for name in sorted(documents):
                _write_bytes(archive, name, documents[name])
            if include_target and target_path is not None:
                _write_file(archive, _TARGET_MEMBER, target_path)
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    return read_bundle(output)


def read_bundle(path: str | Path) -> BundleContents:
    """Read every evidence document after validating paths, sizes, and hashes."""

    bundle_path = Path(path)
    if not bundle_path.is_file():
        raise BundleError(f"bundle does not exist: {bundle_path}")
    bundle_sha256 = _hash_file(bundle_path)[0]
    try:
        with zipfile.ZipFile(bundle_path, mode="r") as archive:
            infos = archive.infolist()
            _validate_archive_members(infos)
            _validate_mimetype(archive, infos[0])
            manifest = _read_json_member(archive, _MANIFEST_MEMBER, _MAX_MANIFEST_BYTES)
            _validate_manifest(archive, manifest)
            briefing = _read_json_member(archive, _BRIEFING_MEMBER, _MAX_JSON_MEMBER_BYTES)
            analysis = _read_json_member(archive, _ANALYSIS_MEMBER, _MAX_JSON_MEMBER_BYTES)
            tools = _read_json_member(archive, _TOOLS_MEMBER, _MAX_JSON_MEMBER_BYTES)
            provenance = (
                _read_json_member(archive, _PROVENANCE_MEMBER, _MAX_JSON_MEMBER_BYTES)
                if _PROVENANCE_MEMBER in archive.namelist()
                else None
            )
            review = (
                _read_json_member(archive, _REVIEW_MEMBER, _MAX_JSON_MEMBER_BYTES)
                if _REVIEW_MEMBER in archive.namelist()
                else None
            )
    except (zipfile.BadZipFile, OSError) as exc:
        raise BundleError(f"invalid r2b bundle: {exc}") from exc

    if briefing.get("schema_version") != "r2b.briefing.v1":
        raise BundleError("briefing.json has an unsupported schema_version")
    if provenance is not None and provenance != analysis.get("provenance"):
        raise BundleError("provenance.json does not match public analysis provenance")
    if review is not None and review.get("schema_version") not in {
        "r2b.review.v1",
        "r2b.review-set.v1",
    }:
        raise BundleError("review.json has an unsupported schema_version")
    return BundleContents(
        path=bundle_path,
        sha256=bundle_sha256,
        manifest=manifest,
        briefing=briefing,
        analysis=analysis,
        tool_status=tools,
        provenance=provenance,
        review=review,
    )


def inspect_bundle(path: str | Path) -> dict[str, Any]:
    """Return a compact summary of a fully validated bundle."""

    return read_bundle(path).summary()


def default_bundle_path(target: str | Path) -> Path:
    """Return ``TARGET`` with its final suffix replaced by ``.r2br``."""

    path = Path(target)
    return path.with_suffix(BUNDLE_EXTENSION) if path.suffix else path.with_name(path.name + BUNDLE_EXTENSION)


def _subject_descriptor(target: Path | None, briefing: Mapping[str, Any]) -> dict[str, Any]:
    if target is None:
        subject = briefing.get("subject")
        source = subject if isinstance(subject, Mapping) else {}
        return {
            "name": Path(str(briefing.get("binary") or "unknown")).name,
            "sha256": source.get("sha256"),
            "size": source.get("size"),
            "bytes_included": False,
        }
    if not target.is_file():
        raise BundleError(f"target is not a regular file: {target}")
    digest, size = _hash_file(target)
    return {
        "name": target.name,
        "sha256": digest,
        "size": size,
        "bytes_included": False,
    }


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    except (TypeError, ValueError) as exc:
        raise BundleError(f"document is not JSON serializable: {exc}") from exc
    return (text + "\n").encode("utf-8")


def _json_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BundleError(f"{label} must be a JSON object")
    try:
        normalized = json.loads(_canonical_json(value))
    except json.JSONDecodeError as exc:  # pragma: no cover - canonical output is valid JSON
        raise BundleError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(normalized, dict):  # pragma: no cover - Mapping always encodes as an object
        raise BundleError(f"{label} must be a JSON object")
    return normalized


def _entry_descriptor(name: str, payload: bytes, role: str) -> dict[str, Any]:
    return {
        "path": name,
        "role": role,
        "media_type": "application/json",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def _role_for(name: str) -> str:
    return {
        _BRIEFING_MEMBER: "briefing",
        _ANALYSIS_MEMBER: "analysis",
        _TOOLS_MEMBER: "tool_status",
        _PROVENANCE_MEMBER: "provenance",
        _REVIEW_MEMBER: "review",
    }[name]


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _write_bytes(archive: zipfile.ZipFile, name: str, payload: bytes) -> None:
    archive.writestr(_zip_info(name), payload, compresslevel=9)


def _write_mimetype(archive: zipfile.ZipFile) -> None:
    info = _zip_info(_MIMETYPE_MEMBER)
    info.compress_type = zipfile.ZIP_STORED
    info.extra = b""
    archive.writestr(info, BUNDLE_MEDIA_TYPE.encode("ascii"))


def _write_file(archive: zipfile.ZipFile, name: str, source: Path) -> None:
    with source.open("rb") as reader, archive.open(_zip_info(name), "w", force_zip64=True) as writer:
        shutil.copyfileobj(reader, writer, length=_COPY_CHUNK)


def _validate_archive_members(infos: list[zipfile.ZipInfo]) -> None:
    if not infos or len(infos) > _MAX_MEMBERS:
        raise BundleError(f"bundle must contain 1-{_MAX_MEMBERS} regular members")
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise BundleError("bundle contains duplicate member names")
    if names[0] != _MIMETYPE_MEMBER:
        raise BundleError("not an r2b evidence bundle: first ZIP member must be mimetype")
    if _MANIFEST_MEMBER not in names:
        raise BundleError("bundle is missing manifest.json")
    for info in infos:
        pure = PurePosixPath(info.filename)
        if (
            info.filename not in _ALLOWED_MEMBERS
            or pure.is_absolute()
            or ".." in pure.parts
            or "\\" in info.filename
            or info.is_dir()
        ):
            raise BundleError(f"unsafe or unknown bundle member: {info.filename!r}")
        if info.flag_bits & 0x1:
            raise BundleError(f"encrypted bundle member is not supported: {info.filename}")
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise BundleError(f"unsupported compression for member: {info.filename}")
        limit = _MAX_TARGET_MEMBER_BYTES if info.filename == _TARGET_MEMBER else _MAX_JSON_MEMBER_BYTES
        if info.filename == _MANIFEST_MEMBER:
            limit = _MAX_MANIFEST_BYTES
        if info.file_size > limit:
            raise BundleError(f"bundle member exceeds size limit: {info.filename}")


def _validate_mimetype(archive: zipfile.ZipFile, first: zipfile.ZipInfo) -> None:
    if first.filename != _MIMETYPE_MEMBER:
        raise BundleError("not an r2b evidence bundle: first ZIP member must be mimetype")
    if first.compress_type != zipfile.ZIP_STORED or first.extra:
        raise BundleError("not an r2b evidence bundle: mimetype must be stored with no extra field")
    try:
        payload = archive.read(first)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BundleError(f"could not read bundle mimetype: {exc}") from exc
    if payload != BUNDLE_MEDIA_TYPE.encode("ascii"):
        raise BundleError("not an r2b evidence bundle: invalid mimetype sentinel")


def _validate_manifest(archive: zipfile.ZipFile, manifest: dict[str, Any]) -> None:
    allowed_manifest_keys = {
        "schema_version",
        "container",
        "producer",
        "subject",
        "entries",
        "requires_scope",
    }
    if set(manifest) - allowed_manifest_keys:
        raise BundleError("manifest.json contains unknown fields")
    if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise BundleError("manifest.json has an unsupported schema_version")
    if manifest.get("container") != "zip":
        raise BundleError("manifest.json container must be zip")
    producer = _object(manifest.get("producer"), "manifest.producer")
    if producer.get("name") != "r2b" or not isinstance(producer.get("version"), str):
        raise BundleError("manifest.json has an invalid producer")
    if "requires_scope" in manifest and not isinstance(manifest["requires_scope"], bool):
        raise BundleError("manifest.requires_scope must be a boolean")
    subject = _object(manifest.get("subject"), "manifest.subject")
    if not isinstance(subject.get("name"), str) or not subject["name"]:
        raise BundleError("manifest.subject.name must be a non-empty string")
    subject_sha = subject.get("sha256")
    if subject_sha is not None and not _is_sha256(subject_sha):
        raise BundleError("manifest.subject.sha256 is invalid")
    subject_size = subject.get("size")
    if subject_size is not None and (not isinstance(subject_size, int) or subject_size < 0):
        raise BundleError("manifest.subject.size is invalid")
    if not isinstance(subject.get("bytes_included"), bool):
        raise BundleError("manifest.subject.bytes_included must be a boolean")
    entries_value = manifest.get("entries")
    if not isinstance(entries_value, list):
        raise BundleError("manifest.entries must be an array")
    entries: dict[str, dict[str, Any]] = {}
    for value in entries_value:
        entry = _object(value, "manifest entry")
        name = entry.get("path")
        if (
            not isinstance(name, str)
            or name in {_MIMETYPE_MEMBER, _MANIFEST_MEMBER}
            or name not in _ALLOWED_MEMBERS
        ):
            raise BundleError("manifest entry has an unsafe or unknown path")
        if name in entries:
            raise BundleError(f"manifest contains duplicate entry: {name}")
        if not _is_sha256(entry.get("sha256")):
            raise BundleError(f"manifest entry has an invalid sha256: {name}")
        if not isinstance(entry.get("size"), int) or entry["size"] < 0:
            raise BundleError(f"manifest entry has an invalid size: {name}")
        expected_role = "target" if name == _TARGET_MEMBER else _role_for(name)
        expected_media = "application/octet-stream" if name == _TARGET_MEMBER else "application/json"
        if entry.get("role") != expected_role or entry.get("media_type") != expected_media:
            raise BundleError(f"manifest entry has invalid role or media type: {name}")
        entries[name] = entry

    archive_names = {info.filename for info in archive.infolist()}
    expected_names = set(entries) | {_MIMETYPE_MEMBER, _MANIFEST_MEMBER}
    if archive_names != expected_names:
        raise BundleError("archive members do not match manifest entries")
    for required in (_BRIEFING_MEMBER, _ANALYSIS_MEMBER, _TOOLS_MEMBER):
        if required not in entries:
            raise BundleError(f"manifest is missing required entry: {required}")
    for name, entry in entries.items():
        digest, size = _hash_archive_member(archive, name)
        if size != entry["size"] or digest != entry["sha256"]:
            raise BundleError(f"bundle member failed hash validation: {name}")

    included = bool(subject.get("bytes_included"))
    if included != (_TARGET_MEMBER in entries):
        raise BundleError("subject bytes_included does not match target.bin presence")
    if included:
        if subject.get("member") != _TARGET_MEMBER:
            raise BundleError("included subject must name target.bin as its member")
        target_entry = entries[_TARGET_MEMBER]
        if subject.get("sha256") != target_entry["sha256"] or subject.get("size") != target_entry["size"]:
            raise BundleError("included target does not match the subject content address")


def _read_json_member(archive: zipfile.ZipFile, name: str, limit: int) -> dict[str, Any]:
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise BundleError(f"bundle is missing {name}") from exc
    if info.file_size > limit:
        raise BundleError(f"bundle member exceeds size limit: {name}")
    try:
        with archive.open(info, "r") as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise BundleError(f"bundle member exceeds size limit: {name}")
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
        raise BundleError(f"invalid JSON member {name}: {exc}") from exc
    return _object(value, name)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError(f"{label} must be a JSON object")
    return value


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(_COPY_CHUNK):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise BundleError(f"could not read {path}: {exc}") from exc
    return digest.hexdigest(), size


def _hash_archive_member(archive: zipfile.ZipFile, name: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(name, "r") as handle:
            while chunk := handle.read(_COPY_CHUNK):
                digest.update(chunk)
                size += len(chunk)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BundleError(f"could not validate bundle member {name}: {exc}") from exc
    return digest.hexdigest(), size


__all__ = [
    "BUNDLE_EXTENSION",
    "BUNDLE_MEDIA_TYPE",
    "BUNDLE_SCHEMA_VERSION",
    "BundleContents",
    "BundleError",
    "create_bundle",
    "default_bundle_path",
    "inspect_bundle",
    "read_bundle",
]
