"""Run extractors with a tight timeout, isolated output dir, and no network.

Uses bubblewrap when present (``--unshare-net``). If bubblewrap is unavailable,
execution fails closed unless the caller explicitly accepts an unsafe subprocess
fallback. Byte and file output is sampled while the process runs and pruned to
the configured limits before results are returned.
"""

from __future__ import annotations

import os
import signal
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True, slots=True)
class ExtractLimits:
    timeout_s: int = 60
    max_files: int = 200
    max_bytes: int = 64 * 1024 * 1024
    max_depth: int = 2
    allow_unsafe_fallback: bool = False


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


_SYSTEM_ROOTS = ("/usr", "/bin", "/lib", "/lib64", "/sbin")
_BLOCKED_BIND_ROOTS = frozenset(
    {
        Path("/"),
        Path("/etc"),
        Path("/var"),
        Path("/tmp"),
        Path("/opt"),
        Path("/home"),
        Path("/root"),
        Path("/nix"),
        Path("/Users"),
        Path("/private"),
        Path("/System"),
        Path("/Applications"),
    }
)


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _too_broad_bind(path: Path) -> bool:
    """True when binding ``path`` would expose a home directory or a system root."""
    try:
        resolved = path.resolve()
    except OSError:
        return True
    if resolved in _BLOCKED_BIND_ROOTS:
        return True
    try:
        home = Path.home().resolve()
    except OSError:
        home = None
    # Bind neither $HOME, nor a parent of it, nor a project dir inside it
    # such as ~/proj when the extractor lives at ~/proj/extractor.
    if home is not None and (
        resolved == home or _is_under(home, resolved) or _is_under(resolved, home)
    ):
        return True
    for root in _SYSTEM_ROOTS:
        root_path = Path(root)
        if resolved == root_path or root_path in resolved.parents:
            return True
    return False


def _tool_path(argv0: str | Path) -> Path | None:
    path = Path(argv0).expanduser()
    if not path.is_absolute():
        return None
    try:
        return path.resolve()
    except OSError:
        return path


def _extractor_ro_binds(argv0: str | Path) -> list[Path]:
    """Read-only binds for an absolute extractor, never a home or system root."""
    tool = _tool_path(argv0)
    if tool is None:
        return []
    binds: list[Path] = []
    if tool.is_file() or tool.exists():
        binds.append(tool)
    parent = tool.parent
    if parent.is_dir() and not _too_broad_bind(parent):
        binds.append(parent)
        lib = parent.parent / "lib"
        if parent.name == "bin" and lib.is_dir() and not _too_broad_bind(lib):
            binds.append(lib)
    # Preserve order, drop duplicates and any leftover broad paths.
    seen: set[Path] = set()
    safe: list[Path] = []
    for item in binds:
        if item in seen or _too_broad_bind(item) and item != tool:
            continue
        seen.add(item)
        safe.append(item)
    return safe


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
    tool_dirs = []
    if argv:
        for bind in _extractor_ro_binds(argv[0]):
            if bind.is_dir():
                tool_dirs.append(str(bind))
            elif bind.parent.is_dir() and not _too_broad_bind(bind.parent):
                tool_dirs.append(str(bind.parent))
    for extra in extra_ro_binds or ():
        resolved = extra.resolve()
        if resolved.is_file():
            tool_dirs.append(str(resolved.parent))
    tool_dirs.extend(["/usr/bin", "/bin"])
    env = {
        # Keep the environment scrubbed while allowing an absolute Homebrew
        # extractor to find sibling helpers such as unsquashfs.
        "PATH": os.pathsep.join(dict.fromkeys(tool_dirs)),
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
    elif limits.allow_unsafe_fallback:
        notes.append(
            "UNSAFE override: bubblewrap missing; extractor ran without filesystem or network isolation"
        )
    else:
        notes.append(
            "extractor blocked: bubblewrap is unavailable and allow_unsafe_fallback is false"
        )
        return SandboxResult(
            argv=list(argv),
            returncode=126,
            stdout="",
            stderr="extractor isolation unavailable",
            timed_out=False,
            sandbox="unavailable",
            output_dir=output_dir,
            notes=notes,
        )

    process = subprocess.Popen(
        wrapped,
        cwd=str(output_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    deadline = time.monotonic() + max(1, limits.timeout_s)
    returncode = 0
    timed_out = False
    stdout = ""
    stderr = ""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            returncode = 124
            notes.append(f"extractor timed out after {limits.timeout_s}s")
            _terminate_process_group(process)
            stdout, stderr = process.communicate()
            break
        try:
            stdout, stderr = process.communicate(timeout=min(0.25, remaining))
            returncode = int(process.returncode or 0)
            break
        except subprocess.TimeoutExpired:
            files, total = _output_usage(output_dir)
            if files > limits.max_files or total > limits.max_bytes:
                returncode = 125
                notes.append(
                    "extractor terminated after crossing the live output limit: "
                    f"{files} files / {total} bytes"
                )
                _terminate_process_group(process)
                stdout, stderr = process.communicate()
                break

    notes.extend(enforce_limits(output_dir, limits))
    return SandboxResult(
        argv=list(argv),
        returncode=returncode,
        stdout=stdout[-8000:],
        stderr=stderr[-8000:],
        timed_out=timed_out,
        sandbox=sandbox,
        output_dir=output_dir,
        notes=notes,
    )


def _output_usage(output_dir: Path) -> tuple[int, int]:
    files = 0
    total = 0
    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            total += path.stat().st_size
            files += 1
        except OSError:
            continue
    return files, total


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()


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
    # An absolute extractor outside the system roots (e.g. a Homebrew prefix)
    # and its sibling helpers must be visible inside the sandbox, read-only.
    if argv:
        for bind in _extractor_ro_binds(argv[0]):
            cmd.extend(["--ro-bind", str(bind), str(bind)])
        # Also mount the original symlink path so a caller can still see it,
        # but execute the resolved pathname so the sandbox can find the tool.
        raw = Path(argv[0]).expanduser()
        if raw.is_absolute() and raw.is_symlink():
            raw_s = str(raw)
            if ("--ro-bind", raw_s) not in zip(cmd, cmd[1:]):
                cmd.extend(["--ro-bind", raw_s, raw_s])
    run_argv = list(argv)
    if argv:
        resolved = _tool_path(argv[0])
        if resolved is not None:
            run_argv[0] = str(resolved)
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
            *run_argv,
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
