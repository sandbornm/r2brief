"""Run extractors with a tight timeout, isolated output dir, and no network.

Uses bubblewrap when present (``--unshare-net``). Falls back to a subprocess
with a scrubbed environment. Neither path is a full VM; both bound depth/size
are enforced by the caller after the process exits.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True, slots=True)
class ExtractLimits:
    timeout_s: int = 60
    max_files: int = 200
    max_bytes: int = 64 * 1024 * 1024
    max_depth: int = 2


@dataclass(slots=True)
class SandboxResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    sandbox: str
    output_dir: Path
    notes: list[str] = field(default_factory=list)


def enforce_limits(output_dir: Path, limits: ExtractLimits) -> list[str]:
    """Delete extracted files past max_files / max_bytes. JSON logs at the root stay."""
    notes: list[str] = []
    if not output_dir.is_dir():
        return notes
    files = [path for path in output_dir.rglob("*") if path.is_file()]
    logs = {path for path in files if path.suffix == ".json" and path.parent == output_dir}
    extracted = [path for path in files if path not in logs]
    extracted.sort(key=lambda path: path.stat().st_size if path.exists() else 0)
    total = 0
    for path in extracted:
        try:
            total += path.stat().st_size
        except OSError:
            continue
    removed = 0
    removed_bytes = 0
    for path in reversed(extracted):
        remaining = len(extracted) - removed
        remaining_bytes = total - removed_bytes
        if remaining <= limits.max_files and remaining_bytes <= limits.max_bytes:
            break
        try:
            size = path.stat().st_size
            path.unlink()
        except OSError:
            continue
        removed += 1
        removed_bytes += size
    if removed:
        notes.append(
            f"pruned {removed} extracted files ({removed_bytes} bytes) to stay within "
            f"{limits.max_files} files / {limits.max_bytes} bytes"
        )
    return notes


def run_sandboxed(
    argv: Sequence[str],
    *,
    input_file: Path,
    output_dir: Path,
    limits: ExtractLimits | None = None,
    extra_ro_binds: Sequence[Path] | None = None,
) -> SandboxResult:
    """Execute ``argv`` with ``output_dir`` writable and the input read-only."""
    limits = limits or ExtractLimits()
    output_dir.mkdir(parents=True, exist_ok=True)
    input_file = input_file.resolve()
    output_dir = output_dir.resolve()
    notes: list[str] = []
    sandbox = "subprocess"
    wrapped = list(argv)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(output_dir),
        "TMPDIR": str(output_dir / "tmp"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    (output_dir / "tmp").mkdir(exist_ok=True)

    bwrap = shutil.which("bwrap")
    if bwrap:
        sandbox = "bwrap"
        wrapped = _bwrap_argv(
            bwrap,
            argv,
            input_file=input_file,
            output_dir=output_dir,
            extra_ro_binds=extra_ro_binds,
        )
        notes.append("extractor ran under bubblewrap --unshare-net")
    else:
        notes.append("bubblewrap missing; extractor ran as a timed subprocess without network isolation")

    try:
        completed = subprocess.run(
            wrapped,
            cwd=str(output_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=max(1, limits.timeout_s),
            check=False,
        )
        notes.extend(enforce_limits(output_dir, limits))
        return SandboxResult(
            argv=list(argv),
            returncode=completed.returncode,
            stdout=completed.stdout[-8000:],
            stderr=completed.stderr[-8000:],
            timed_out=False,
            sandbox=sandbox,
            output_dir=output_dir,
            notes=notes,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"") if isinstance(exc.stdout, (bytes, bytearray)) else (exc.stdout or "")
        stderr = (exc.stderr or b"") if isinstance(exc.stderr, (bytes, bytearray)) else (exc.stderr or "")
        if isinstance(stdout, (bytes, bytearray)):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, (bytes, bytearray)):
            stderr = stderr.decode("utf-8", "replace")
        notes.append(f"extractor timed out after {limits.timeout_s}s")
        notes.extend(enforce_limits(output_dir, limits))
        return SandboxResult(
            argv=list(argv),
            returncode=124,
            stdout=str(stdout)[-8000:],
            stderr=str(stderr)[-8000:],
            timed_out=True,
            sandbox=sandbox,
            output_dir=output_dir,
            notes=notes,
        )


def _bwrap_argv(
    bwrap: str,
    argv: Sequence[str],
    *,
    input_file: Path,
    output_dir: Path,
    extra_ro_binds: Sequence[Path] | None,
) -> list[str]:
    cmd: list[str] = [
        bwrap,
        "--unshare-net",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    for root in ("/usr", "/bin", "/lib", "/lib64", "/sbin"):
        path = Path(root)
        if path.exists():
            cmd.extend(_bind_or_symlink(path))
    # Interpreter and dynamic linker live here on Debian usrmerge hosts.
    for extra in extra_ro_binds or ():
        resolved = extra.resolve()
        if resolved.exists():
            cmd.extend(["--ro-bind", str(resolved), str(resolved)])
    cmd.extend(
        [
            "--ro-bind",
            str(input_file),
            str(input_file),
            "--bind",
            str(output_dir),
            str(output_dir),
            "--chdir",
            str(output_dir),
            "--",
            *argv,
        ]
    )
    return cmd


def _bind_or_symlink(path: Path) -> list[str]:
    if path.is_symlink():
        target = os.readlink(path)
        return ["--symlink", target, str(path)]
    if path.is_dir() or path.is_file():
        return ["--ro-bind", str(path), str(path)]
    return []
