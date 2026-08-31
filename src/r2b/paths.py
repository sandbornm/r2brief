"""Checkout vs wheel path helpers.

The published wheel is CLI-only. A git checkout should still `uv sync` and
run. Config ships inside the package so `r2b setup` works without the repo.
"""

from __future__ import annotations

from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent


def find_checkout_root(start: Path | None = None, *, include_cwd: bool = True) -> Path | None:
    """Return the repo root if this is an editable checkout, else None."""
    seen: set[Path] = set()
    candidates: list[Path] = []
    here = (start or Path(__file__)).resolve()
    candidates.append(here)
    candidates.extend(here.parents)
    if include_cwd:
        cwd = Path.cwd().resolve()
        candidates.append(cwd)
        candidates.extend(cwd.parents)
    for parent in candidates:
        if parent in seen:
            continue
        seen.add(parent)
        if (parent / "pyproject.toml").is_file() and (parent / "src" / "r2b").is_dir():
            return parent
    return None


def shipped_config_dir() -> Path:
    """config/ in a checkout, or r2b/share/ baked into the wheel."""
    checkout = find_checkout_root(include_cwd=False)
    if checkout is not None:
        return checkout / "config"
    return _PKG_DIR / "share"


__all__ = ["find_checkout_root", "shipped_config_dir"]
