"""Static verification of dangerous-import call sites.

Turns a triage hypothesis ("popen might be attacker-controlled") into a
fact ("popen argument is the constant 'ifconfig ra0'") by resolving the
first argument register at every call site of the import.

Works from radare2 disassembly text and makes no attempt to be a full
dataflow engine: it resolves lui/addiu + move chains a bounded window
before each call site and classifies what feeds argument register a0
(x86: rdi/rdi-equivalent first argument naming is arch-specific; the
resolver keys on the arch's first-argument register reported by radare2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Dangerous imports worth verifying by default.
DEFAULT_IMPORTS: tuple[str, ...] = (
    "system",
    "popen",
    "execv",
    "execve",
    "execl",
    "execvp",
)

# Argument register by radare2 arch name (first integer argument).
_ARG_REGS: dict[str, tuple[str, ...]] = {
    "mips": ("a0",),
    "arm": ("r0",),
    "aarch64": ("x0", "w0"),
    "x86": ("rdi", "edi", "di"),
    "x64": ("rdi", "edi", "di"),
    "ppc": ("r3",),
}

_INSN_RE = re.compile(
    r"^[\s│┎┃╎╭├└─]*(?P<addr>0x[0-9a-f]+)\s+(?P<bytes>[0-9a-f]{4,16})\s+(?P<mnem>[a-z.][a-z0-9.]*)\s*(?P<ops>.*)$",
    re.IGNORECASE,
)

_STRING_RE = re.compile(r";\s*\"(?P<str>(?:[^\"\\]|\\.)*)\"")

_HEX_PAIR_RE = re.compile(
    r"(?P<reg>a[0-3]|v[0-1]|s[0-7]|t[0-9]|r[0-9]|x[0-9]+|w[0-9]+|rdi|edi|di|zero),\s*(?P<val>-?0x[0-9a-f]+)"
)


@dataclass(slots=True)
class CallSite:
    """One call site of a dangerous import."""

    function: str
    address: str
    argument: str  # resolved constant string, or "<dynamic>" / "<unresolved>"
    is_constant: bool = False
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ImportVerdict:
    """Verification result for one import."""

    import_name: str
    call_sites: list[CallSite] = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.call_sites:
            return "no-callers"
        if all(cs.is_constant for cs in self.call_sites):
            return "all-constant"
        if any(cs.is_constant for cs in self.call_sites):
            return "mixed"
        return "dynamic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "import": self.import_name,
            "status": self.status,
            "call_sites": [
                {
                    "function": cs.function,
                    "address": cs.address,
                    "argument": cs.argument,
                    "constant": cs.is_constant,
                }
                for cs in self.call_sites
            ],
        }


def first_arg_registers(arch: str | None) -> tuple[str, ...]:
    """Return candidate first-argument registers for a radare2 arch string."""
    if not arch:
        return ("a0", "rdi", "r0", "x0")
    lowered = arch.lower()
    for key, regs in _ARG_REGS.items():
        if key in lowered:
            return regs
    return ("a0", "rdi", "r0", "x0")


def parse_disassembly_line(line: str) -> tuple[str, str, str] | None:
    """Return (addr, mnemonic, operands) for one pd line, else None."""
    match = _INSN_RE.match(line)
    if not match:
        return None
    return match.group("addr"), match.group("mnem").lower(), match.group("ops")

def extract_comment_string(line: str) -> str | None:
    """Return a useful string literal from a radare2 trailing comment.

    Source-location crumbs (``.c:215``, ``tdpdServer.c:377``) are ignored so
    they never masquerade as the call argument.
    """
    match = _STRING_RE.search(line)
    if not match:
        return None
    text = match.group("str")
    if re.fullmatch(r"(?:[A-Za-z0-9_./-]+\.c:\d+|\.?c:\d+)", text):
        return None
    return text


def _window_instructions(lines: list[str], index: int, size: int = 8) -> list[str]:
    return lines[max(0, index - size) : index + 1]


def resolve_argument(
    lines: list[str],
    call_index: int,
    arg_regs: tuple[str, ...],
) -> CallSite:
    """Classify the value in the first argument register at lines[call_index].

    Bounded static walk: looks back a fixed window, follows one move/addiu
    indirection, and trusts radare2's comment annotations for rodata strings.
    """
    window = _window_instructions(lines, call_index)
    call_addr, _, _ = parse_disassembly_line(window[-1]) or ("?", "", "")
    function = next(
        (caller for line in reversed(window) if (caller := _caller_marker(line)) is not None),
        _function_name_for_line(window[-1]),
    )
    evidence: list[str] = [line.strip() for line in window[-4:]]
    site = CallSite(function=function, address=call_addr, argument="<unresolved>", evidence=evidence)

    # Scan backwards for the most recent write to an argument register.
    for line in reversed(window[:-1]):
        parsed = parse_disassembly_line(line)
        if not parsed:
            continue
        _, mnem, ops = parsed
        for reg in arg_regs:
            if _writes_register(mnem, ops, reg):
                comment = extract_comment_string(line)
                if comment is not None:
                    site.argument = comment
                    site.is_constant = True
                    return site
                # lui reg, imm followed later by addiu reg, reg, off means a
                # rodata address; the comment usually rides on the addiu.
                if mnem.startswith("lui"):
                    partner = _find_addiu_pair(window, reg)
                    if partner is not None:
                        site.argument = partner
                        site.is_constant = True
                        return site
                if mnem.startswith(("move", "ori")) and reg in arg_regs:
                    site.argument = "<dynamic>"
                    return site
                # Register-to-register copy from another register: give up
                # beyond one hop -- classify as dynamic rather than guess.
                site.argument = "<dynamic>"
                return site
        # Annotate from any line in the window that names a rodata string.
    site.argument = "<unresolved>"
    return site


def _writes_register(mnem: str, ops: str, reg: str) -> bool:
    """True when the instruction's destination operand is ``reg``."""
    if not ops:
        return False
    dest = ops.split(",")[0].strip()
    return dest == reg


def _find_addiu_pair(window: list[str], reg: str) -> str | None:
    """Find an addiu on ``reg`` in the window and return its string comment."""
    for line in window:
        parsed = parse_disassembly_line(line)
        if not parsed:
            continue
        _, mnem, ops = parsed
        if not mnem.startswith(("addiu", "addi", "ori")):
            continue
        dest = ops.split(",")[0].strip()
        if dest != reg:
            continue
        comment = extract_comment_string(line)
        if comment is not None:
            return comment
    return None


def _function_name_for_line(line: str) -> str:
    """Extract sym./fcn. name from a call line's annotation, if present."""
    match = re.search(r"(?:sym|fcn)\.([A-Za-z0-9_.]+)", line)
    if match:
        return match.group(1)
    match = re.search(r";\s*([A-Za-z_][A-Za-z0-9_]*)\(", line)
    if match:
        return match.group(1)
    return "unknown"


def _caller_marker(line: str) -> str | None:
    """Return the caller name attached by the radare2 adapter, if present."""
    match = re.search(r";\s*r2b-caller:\s*(?:sym\.|fcn\.)?([A-Za-z0-9_.]+)", line)
    return match.group(1) if match else None


def _dedupe_call_sites(call_sites: list[CallSite]) -> list[CallSite]:
    """Merge overlapping disassembly windows for the same call address."""
    unique: dict[str, CallSite] = {}
    for site in call_sites:
        existing = unique.get(site.address)
        if existing is None:
            unique[site.address] = site
            continue
        if existing.function == "unknown" and site.function != "unknown":
            existing.function = site.function
        existing_rank = 0 if existing.argument == "<unresolved>" else 1 + int(existing.is_constant)
        site_rank = 0 if site.argument == "<unresolved>" else 1 + int(site.is_constant)
        if site_rank > existing_rank:
            existing.argument = site.argument
            existing.is_constant = site.is_constant
            existing.evidence = site.evidence
    return list(unique.values())


def verify_imports(
    xref_lines: dict[str, list[str]],
    arch: str | None,
) -> list[ImportVerdict]:
    """Verify dangerous imports from radare2 axt/pd output.

    ``xref_lines`` maps import name -> list of disassembly lines around each
    call site (as produced by ``pd`` windows containing the call).
    """
    arg_regs = first_arg_registers(arch)
    verdicts: list[ImportVerdict] = []
    for import_name, lines in xref_lines.items():
        verdict = ImportVerdict(import_name=import_name)
        current: list[str] = []
        for line in lines:
            current.append(line)
            parsed = parse_disassembly_line(line)
            if not parsed:
                continue
            _, mnem, ops = parsed
            references_import = import_name in ops
            is_call = mnem in {"bl", "blr", "jal", "jalr", "call", "callq"}
            if is_call:
                # Direct jal sym.imp.X names the import; an indirect jalr is
                # a call site only when the recent window loaded that import
                # through the GOT (lw t9, -sym.imp.X(gp) pattern).
                if references_import or _window_references(current[:-1], import_name):
                    verdict.call_sites.append(resolve_argument(current, len(current) - 1, arg_regs))
                    current = []
        verdict.call_sites = _dedupe_call_sites(verdict.call_sites)
        verdicts.append(verdict)
    return verdicts


def _window_references(window: list[str], import_name: str) -> bool:
    return any(import_name in line for line in window)
