"""Small input-hardening helpers shared by the web app and compiler wrappers.

These exist so request-controlled values are validated in one place before
they reach the filesystem, a subprocess argv, a shell string, or a log line.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path

_LOG_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]")


class UnsafeInputError(ValueError):
    """Raised when a request-controlled value fails validation."""


def sanitize_log(value: object, max_len: int = 500) -> str:
    """Return ``value`` as one log-safe line.

    CR/LF (and other control characters) are escaped so a caller cannot forge
    additional log records; long values are truncated.
    """
    text = str(value)
    if len(text) > max_len:
        text = text[:max_len] + "..."
    text = text.replace("\r\n", "\\r\\n").replace("\n", "\\n").replace("\r", "\\r")
    return _LOG_CONTROL_RE.sub("?", text)


def reject_option_like(value: str, *, field: str = "value") -> str:
    """Reject empty values, NUL bytes and values that a tool would parse as an option."""
    if not isinstance(value, str) or not value:
        raise UnsafeInputError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise UnsafeInputError(f"{field} contains a NUL byte")
    if value.startswith("-"):
        raise UnsafeInputError(f"{field} must not start with '-'")
    return value


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def resolve_within(
    candidate: str | Path,
    roots: Iterable[str | Path],
    *,
    field: str = "path",
) -> Path:
    """Resolve ``candidate`` and require it to live under one of ``roots``.

    Symlinks and ``..`` segments are resolved first, so neither can be used to
    escape. Relative candidates are interpreted relative to the first root.
    Returns the resolved absolute path of something *inside* a root (the root
    directory itself is not accepted); raises :class:`UnsafeInputError`.
    """
    resolved_roots = [os.path.realpath(os.path.expanduser(str(root))) for root in roots]
    if not resolved_roots:
        raise UnsafeInputError(f"{field} is not allowed: no permitted directories configured")
    raw = str(candidate)
    if not raw or "\x00" in raw:
        raise UnsafeInputError(f"{field} is invalid")
    # An absolute ``raw`` replaces the join base, so relative and absolute inputs share this path.
    fullpath = os.path.realpath(os.path.join(resolved_roots[0], os.path.expanduser(raw)))
    for root in resolved_roots:
        if fullpath.startswith(os.path.join(root, "")):
            return Path(fullpath)
    raise UnsafeInputError(f"{field} is outside the permitted directories")


_STEM_RE = re.compile(r"[^A-Za-z0-9_-]+")


def safe_stem(name: str, default: str = "output", max_len: int = 64) -> str:
    """Reduce a user-supplied output name to a plain, option-safe file stem.

    Any extension is dropped and only ``[A-Za-z0-9_-]`` is kept, so the result has
    no separators, dots, or leading ``-``.
    """
    base = Path(str(name).replace("\\", "/")).name
    if "." in base:
        base = base.rsplit(".", 1)[0]
    base = _STEM_RE.sub("_", base).strip("_-")[:max_len]
    return base or default


__all__ = [
    "UnsafeInputError",
    "is_relative_to",
    "reject_option_like",
    "resolve_within",
    "safe_stem",
    "sanitize_log",
]
