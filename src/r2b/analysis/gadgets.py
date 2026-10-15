"""Optional post-verify static gadget / ROP scan.

Off by default. Uses radare2 ``/R`` when available (``/g`` only after a
rename reject such as ``/R is now known as /g`` on 6.2.x), else ROPgadget.
Never executes the target; output is bounded and deterministic. A rejected
radare2 command never reports ``status=ok``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GADGETS_SCHEMA_VERSION = "r2b.gadgets.v1"
DEFAULT_LIMIT = 32
_MAX_LIMIT = 128
_TIMEOUT_SEC = 30
_GADGET_LINE_RE = re.compile(
    r"(?P<addr>0x[0-9a-fA-F]+)\s*(?::|\s)\s*(?P<body>.+)$"
)
# 6.2.x renamed ROP search /R → /g. On 6.0.x /g is graph-paths, not ROP.
_R2_RENAME_HINT_RE = re.compile(
    r"/R\s+is\s+now\s+known\s+as\s+/g|unknown\s+command\s+['\"]?/R",
    re.IGNORECASE,
)


class GadgetScanError(ValueError):
    """The gadget engine rejected the command or failed."""


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

    last_error: str | None = None
    last_status = "failed"
    for name, runner in engines:
        try:
            hits = runner(path, capped)
        except GadgetScanError as exc:
            last_error = f"{name}: {exc}"
            last_status = "unsupported" if "unsupported" in str(exc).lower() else "failed"
            continue
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            last_error = f"{name}: {exc}"
            last_status = "failed"
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
        "status": last_status,
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


def preferred_radare2_rop_command(version_text: str = "") -> str:
    """Return the first ROP search command to try.

    Prefer legacy ``/R``. Only jump straight to ``/g`` when the version banner
    clearly indicates the 6.2+ rename (``/R is now known as /g`` era). On
    6.0.x ``/g`` is graph-path search, not ROP.
    """

    text = version_text or ""
    # Explicit rename era: 6.2+
    match = re.search(r"radare2\s+(\d+)\.(\d+)", text, re.IGNORECASE)
    if match is not None:
        major, minor = int(match.group(1)), int(match.group(2))
        if (major, minor) >= (6, 2):
            return "/g"
    return "/R"


def _probe_radare2_version() -> str:
    completed = subprocess.run(
        ["radare2", "-v"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return (completed.stdout or "") + (completed.stderr or "")


def _run_radare2_rop_cmd(path: Path, command: str) -> subprocess.CompletedProcess[str]:
    # Bound client-side; do not pass a numeric arg (``/g N`` is an address on
    # 6.0.x graph-path search, and ``/R N`` is a search string).
    cmd = [
        "radare2",
        "-q",
        "-e",
        "scr.color=0",
        "-e",
        "scr.interactive=false",
        "-e",
        "bin.relocs.apply=true",
        "-c",
        command,
        str(path),
    ]
    return subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SEC,
    )


def _output_rejects_legacy_R(text: str) -> bool:
    return bool(_R2_RENAME_HINT_RE.search(text or ""))


def _scan_radare2(path: Path, limit: int) -> list[GadgetHit]:
    version_text = _probe_radare2_version()
    primary = preferred_radare2_rop_command(version_text)
    # Always keep the other spelling as fallback when the primary is rejected.
    candidates = [primary]
    alt = "/g" if primary == "/R" else "/R"
    if alt not in candidates:
        candidates.append(alt)

    last_reject: str | None = None
    for command in candidates:
        completed = _run_radare2_rop_cmd(path, command)
        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        if command == "/R" and _output_rejects_legacy_R(combined):
            last_reject = combined.strip().splitlines()[0] if combined.strip() else "/R rejected"
            continue
        if _output_rejects_legacy_R(combined) and command == "/R":
            last_reject = combined.strip().splitlines()[0]
            continue
        if completed.returncode not in {0, 1}:
            last_reject = f"radare2 {command} exited {completed.returncode}"
            continue
        # Graph-path /g on 6.0.x emits "Cannot find basic block" — not ROP.
        if re.search(r"Cannot find basic block", combined, re.IGNORECASE):
            last_reject = f"{command}: not a ROP search on this radare2 build"
            continue
        hits = _parse_gadget_lines(combined, limit)
        if hits:
            return hits
        # Empty listing without a reject message is a valid empty ROP result.
        if not _output_rejects_legacy_R(combined) and "ERROR:" not in combined:
            return hits
        last_reject = f"{command}: no usable gadget listing"
    raise GadgetScanError(
        last_reject or "unsupported: radare2 ROP search (/R or /g) unavailable"
    )


def _scan_ropgadget(path: Path, limit: int) -> list[GadgetHit]:
    binary = shutil.which("ROPgadget") or shutil.which("ropgadget")
    if binary is None:
        raise FileNotFoundError("ROPgadget not found")
    cmd = [binary, "--binary", str(path), "--norop", "--nojop", "--noshort", "--all"]
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
        if _output_rejects_legacy_R(line):
            continue
        if line.startswith("WARN:") or line.startswith("ERROR:"):
            continue
        match = _GADGET_LINE_RE.search(line)
        if match is None:
            continue
        address = match.group("addr").lower()
        body = match.group("body").strip()
        if body.startswith(":"):
            body = body[1:].strip()
        key = f"{address}|{body}"
        if key in seen:
            continue
        seen.add(key)
        hits.append(GadgetHit(address=address, instructions=body))
        if len(hits) >= limit:
            break
    hits.sort(key=lambda hit: (int(hit.address, 16), hit.instructions))
    return hits[:limit]


__all__ = [
    "DEFAULT_LIMIT",
    "GADGETS_SCHEMA_VERSION",
    "GadgetHit",
    "GadgetScanError",
    "preferred_radare2_rop_command",
    "scan_gadgets",
]
