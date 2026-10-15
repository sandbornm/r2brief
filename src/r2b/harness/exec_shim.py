"""Allowlisted ``r2b-exec`` shim for external planners.

Only forwards known ``r2b`` subcommands. Never shells a free-form string,
never executes analysis targets, and never invokes a model.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

ALLOWED_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "env",
        "setup",
        "brief",
        "verify",
        "diff",
        "decompile",
        "records",
        "insights",
        "review",
        "bundle",
        "ghidra",
        "version",
    }
)

_DENIED_EXIT = 64


def run_allowlisted(argv: Sequence[str] | None = None) -> int:
    """Validate argv and exec ``r2b`` with the same argument vector.

    ``argv`` is the shim argv (``r2b-exec …``). The first element may be the
    program name; remaining tokens must start with an allowlisted subcommand
    or ``--version`` / ``-h`` / ``--help``.
    """

    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0].endswith(("r2b-exec", "r2b_exec.py")):
        args = args[1:]
    if not args:
        sys.stderr.write(
            "r2b-exec: missing subcommand. Allowed: "
            + ", ".join(sorted(ALLOWED_SUBCOMMANDS))
            + "\n"
        )
        return _DENIED_EXIT
    head = args[0]
    if head in {"-h", "--help"}:
        sys.stdout.write(
            "Usage: r2b-exec SUBCOMMAND [args…]\n"
            "Allowlisted r2b subcommands only. Analysis never calls a model;\n"
            "targets are never executed.\n"
            f"Allowed: {', '.join(sorted(ALLOWED_SUBCOMMANDS))}\n"
        )
        return 0
    if head in {"--version", "-V"}:
        # Forward to r2b --version
        return _exec_r2b(["--version"])
    # Nested groups: `records list`, `bundle create`, `ghidra …`
    sub = head
    if sub not in ALLOWED_SUBCOMMANDS:
        sys.stderr.write(
            f"r2b-exec: subcommand not allowlisted: {sub!r}\n"
            f"Allowed: {', '.join(sorted(ALLOWED_SUBCOMMANDS))}\n"
        )
        return _DENIED_EXIT
    return _exec_r2b(args)


def _exec_r2b(args: list[str]) -> int:
    # Prefer in-process Typer invoke so tests and slim images need no PATH hop.
    # Fall back to os.execvp when R2B_EXEC_SPAWN=1 (real process boundary).
    if os.environ.get("R2B_EXEC_SPAWN") == "1":
        os.execvp("r2b", ["r2b", *args])
        return 127  # pragma: no cover
    from r2b.cli import app

    try:
        app(args=args, prog_name="r2b", standalone_mode=False)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        sys.stderr.write(str(code) + "\n")
        return 1
    return 0


def main() -> None:
    raise SystemExit(run_allowlisted())


if __name__ == "__main__":
    main()
