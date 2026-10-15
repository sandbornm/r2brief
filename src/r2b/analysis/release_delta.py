"""SHA-256 release-delta over two extracted firmware / rootfs trees.

Walks both trees, hashes every regular file, and reports the set of files
common to both whose contents changed, flagging ELF binaries. This is the
deterministic reduction that turns "two firmware images" into "these N
changed ELFs" before ``brief`` / ``verify`` ever open a binary.

Pure stdlib + pathlib. No network, no radare2, no unpacker — input trees
are assumed already extracted. Symlinks are skipped so host/container
layout noise does not inflate the delta.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = "r2b.release_delta.v1"
_CHUNK = 1 << 20
_ELF_MAGIC = b"\x7fELF"


@dataclass(frozen=True)
class FileEntry:
    """One regular file under a rootfs tree."""

    relpath: str
    sha256: str
    is_elf: bool
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "relpath": self.relpath,
            "sha256": self.sha256,
            "is_elf": self.is_elf,
            "size": self.size,
        }


@dataclass(frozen=True)
class ChangedFile:
    """A path present in both trees whose content (SHA-256) differs."""

    relpath: str
    a_sha256: str
    b_sha256: str
    a_size: int
    b_size: int
    is_elf: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "relpath": self.relpath,
            "a_sha256": self.a_sha256,
            "b_sha256": self.b_sha256,
            "a_size": self.a_size,
            "b_size": self.b_size,
            "is_elf": self.is_elf,
        }


@dataclass(frozen=True)
class ReleaseDelta:
    """Result of comparing two extracted trees by content hash."""

    a_root: str
    b_root: str
    common: tuple[str, ...]
    only_a: tuple[str, ...]
    only_b: tuple[str, ...]
    changed: tuple[ChangedFile, ...]
    schema_version: str = SCHEMA_VERSION

    @property
    def changed_elfs(self) -> tuple[ChangedFile, ...]:
        return tuple(item for item in self.changed if item.is_elf)

    @property
    def unchanged_count(self) -> int:
        return len(self.common) - len(self.changed)

    def reduction(self) -> dict[str, int]:
        """Flagship reduction numbers: common -> changed -> changed ELFs."""
        return {
            "common_files": len(self.common),
            "only_in_a": len(self.only_a),
            "only_in_b": len(self.only_b),
            "changed_common_files": len(self.changed),
            "changed_common_elfs": len(self.changed_elfs),
            "unchanged_common_files": self.unchanged_count,
        }

    def to_dict(self, *, include_paths: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "a_root": self.a_root,
            "b_root": self.b_root,
            "reduction": self.reduction(),
            "changed_elfs": [item.to_dict() for item in self.changed_elfs],
        }
        if include_paths:
            payload["changed"] = [item.to_dict() for item in self.changed]
            payload["only_a"] = list(self.only_a)
            payload["only_b"] = list(self.only_b)
        return payload


def file_sha256(path: Path) -> str:
    """Stream a file's SHA-256 as lowercase hex."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_elf(path: Path) -> bool:
    """True when the file begins with the ELF magic bytes."""
    try:
        with path.open("rb") as handle:
            return handle.read(4) == _ELF_MAGIC
    except OSError:
        return False


def index_tree(root: Path) -> dict[str, FileEntry]:
    """Hash every regular (non-symlink) file under ``root``.

    Relative paths use POSIX separators so the same tree compared on
    different hosts produces identical keys.
    """
    root = root.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"not a directory: {root}")
    out: dict[str, FileEntry] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        out[rel] = FileEntry(
            relpath=rel,
            sha256=file_sha256(path),
            is_elf=is_elf(path),
            size=path.stat().st_size,
        )
    return out


def compare_trees(
    a_root: Path | str,
    b_root: Path | str,
    *,
    a_index: Mapping[str, FileEntry] | None = None,
    b_index: Mapping[str, FileEntry] | None = None,
) -> ReleaseDelta:
    """Compare two extracted trees and return the SHA-256 release delta.

    Matching SHA-256 on a common path means "not this release's question."
    The ``changed_elfs`` list is the set r2b should brief next.
    """
    a_path = Path(a_root)
    b_path = Path(b_root)
    a = dict(a_index) if a_index is not None else index_tree(a_path)
    b = dict(b_index) if b_index is not None else index_tree(b_path)
    common = tuple(sorted(set(a) & set(b)))
    only_a = tuple(sorted(set(a) - set(b)))
    only_b = tuple(sorted(set(b) - set(a)))
    changed: list[ChangedFile] = []
    for rel in common:
        left, right = a[rel], b[rel]
        if left.sha256 == right.sha256:
            continue
        changed.append(
            ChangedFile(
                relpath=rel,
                a_sha256=left.sha256,
                b_sha256=right.sha256,
                a_size=left.size,
                b_size=right.size,
                is_elf=left.is_elf or right.is_elf,
            )
        )
    return ReleaseDelta(
        a_root=str(a_path),
        b_root=str(b_path),
        common=common,
        only_a=only_a,
        only_b=only_b,
        changed=tuple(changed),
    )


def iter_changed_elf_paths(delta: ReleaseDelta) -> Iterable[str]:
    """Yield relative paths of changed ELFs (stable order)."""
    for item in delta.changed_elfs:
        yield item.relpath


__all__ = [
    "SCHEMA_VERSION",
    "ChangedFile",
    "FileEntry",
    "ReleaseDelta",
    "compare_trees",
    "file_sha256",
    "index_tree",
    "is_elf",
    "iter_changed_elf_paths",
]
