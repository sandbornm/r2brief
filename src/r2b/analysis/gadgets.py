"""Optional post-verify static gadget / ROP scan.

Off by default. Uses radare2 ``/R`` when available, else ROPgadget.
Never executes the target; output is bounded and deterministic.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable
from typing import Any

GADGETS_SCHEMA_VERSION = "r2b.gadgets.v1"
DEFAULT_LIMIT = 32
_MAX_LIMIT = 128
_TIMEOUT_SEC = 30
_GADGET_LINE_RE = re.compile(
    r"(?P<addr>0x[0-9a-fA-F]+)\s*(?::|\s)\s*(?P<body>.+)$"
)


@dataclass(frozen=True, slots=True)
class GadgetHit:
    address: str
    instructions: str

    def to_dict(self) -> dict[str, str]:
        return {"address": self.address.lower(), "instructions": self.instructions}


def scan_gadgets(
    binary: str | Path,
    *,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Return a bounded gadget listing for ``binary``."""

    path = Path(binary)
    if not path.is_file():
        return {
            "schema_version": GADGETS_SCHEMA_VERSION,
            "binary": str(path),
            "status": "missing",
            "engine": None,
            "limit": _clamp_limit(limit),
            "count": 0,
            "gadgets": [],
            "note": f"binary does not exist: {path}",
        }
    capped = _clamp_limit(limit)
    engines: list[tuple[str, Callable[[Path, int], list[GadgetHit]]]] = []
    if shutil.which("radare2") is not None:
        engines.append(("radare2", _scan_radare2))
    if shutil.which("ROPgadget") is not None or shutil.which("ropgadget") is not None:
        engines.append(("ROPgadget", _scan_ropgadget))
    if not engines:
        return {
            "schema_version": GADGETS_SCHEMA_VERSION,
            "binary": str(path),
            "status": "skipped",
            "engine": None,
            "limit": capped,
            "count": 0,
            "gadgets": [],
            "note": "neither radare2 nor ROPgadget is installed",
        }

    last_error = None
    for name, runner in engines:
        try:
            hits = runner(path, capped)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            last_error = f"{name}: {exc}"
            continue
        return {
            "schema_version": GADGETS_SCHEMA_VERSION,
            "binary": str(path),
            "status": "ok",
            "engine": name,
            "limit": capped,
            "count": len(hits),
            "gadgets": [hit.to_dict() for hit in hits],
            "note": None if hits else "no gadgets reported within the bound",
        }
    return {
        "schema_version": GADGETS_SCHEMA_VERSION,
        "binary": str(path),
        "status": "error",
        "engine": None,
        "limit": capped,
        "count": 0,
        "gadgets": [],
        "note": last_error or "gadget scan failed",
    }


def _clamp_limit(limit: int) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_LIMIT
    if value < 1:
        return 1
    return min(value, _MAX_LIMIT)


def _scan_radare2(path: Path, limit: int) -> list[GadgetHit]:
    # /R is radare2's ROP gadget search; -q quiet, -c single command, -e no color.
    cmd = [
        "radare2",
        "-q",
        "-e",
        "scr.color=0",
        "-e",
        "scr.interactive=false",
        "-c",
        f"/R {limit}",
        str(path),
    ]
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SEC,
    )
    if completed.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(
            completed.returncode, cmd, output=completed.stdout, stderr=completed.stderr
        )
    return _parse_gadget_lines(completed.stdout or completed.stderr or "", limit)


def _scan_ropgadget(path: Path, limit: int) -> list[GadgetHit]:
    binary = shutil.which("ROPgadget") or shutil.which("ropgadget")
    if binary is None:
        raise FileNotFoundError("ROPgadget not found")
    cmd = [binary, "--binary", str(path), "--norop", "--nojop", "--noshort", "--all"]
    # Prefer a cheaper depth-bounded search when supported; fall back otherwise.
    cmd_depth = [binary, "--binary", str(path), "--depth", "5"]
    completed = subprocess.run(
        cmd_depth,
        check=False,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SEC,
    )
    if completed.returncode != 0:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SEC,
        )
    if completed.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(
            completed.returncode, cmd_depth, output=completed.stdout, stderr=completed.stderr
        )
    return _parse_gadget_lines(completed.stdout or "", limit)


def _parse_gadget_lines(text: str, limit: int) -> list[GadgetHit]:
    hits: list[GadgetHit] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "Gadgets information" in line:
            continue
        if line.lower().startswith(("unique gadgets", "found", "gadget search")):
            continue
        match = _GADGET_LINE_RE.search(line)
        if match is None:
            continue
        address = match.group("addr").lower()
        body = match.group("body").strip()
        # ROPgadget uses "0xaddr : insn ; insn"
        if body.startswith(":"):
            body = body[1:].strip()
        key = f"{address}|{body}"
        if key in seen:
            continue
        seen.add(key)
        hits.append(GadgetHit(address=address, instructions=body))
        if len(hits) >= limit:
            break
    # Stable order: address then instructions.
    hits.sort(key=lambda hit: (int(hit.address, 16), hit.instructions))
    return hits[:limit]


__all__ = [
    "DEFAULT_LIMIT",
    "GADGETS_SCHEMA_VERSION",
    "GadgetHit",
    "scan_gadgets",
]
