from __future__ import annotations

import re
from dataclasses import dataclass, field
from collections.abc import Iterable
from typing import Any

DEFAULT_IMPORTS: tuple[str, ...] = (
    "system",
    "popen",
    "execv",
    "execve",
    "execl",
    "execvp",
)


def collect_verify_names(*groups: Iterable[str], limit: int = 8) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for raw in group:
            name = str(raw or "").strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(name)
            if len(names) >= limit:
                return names
    return names

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

_FUNCTION_VA_RE = re.compile(
    r"(?:(?:sym|fcn|sub|func)\.)?(?:0x)?([0-9a-f]{3,16})$",
    re.IGNORECASE,
)


def format_function_va(offset: int) -> str:
    if offset < 0x100000000:
        return f"0x{offset:08x}"
    return f"0x{offset:x}"


def parse_function_va(value: str | int | None) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        if value <= 0:
            return None
        return format_function_va(value)
    text = str(value).strip()
    if not text:
        return None
    match = _FUNCTION_VA_RE.fullmatch(text)
    if match is None:
        embedded = re.search(r"0x([0-9a-f]+)", text, re.IGNORECASE)
        if embedded is None:
            return None
        offset = int(embedded.group(1), 16)
        return format_function_va(offset) if offset > 0 else None
    offset = int(match.group(1), 16)
    if offset <= 0:
        return None
    return format_function_va(offset)


@dataclass(slots=True)
class CallSite:

    function: str
    address: str
    argument: str
    is_constant: bool = False
    evidence: list[str] = field(default_factory=list)
    function_addr: str | None = None


@dataclass(slots=True)
class ImportVerdict:

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
                    "function_addr": cs.function_addr,
                    "address": cs.address,
                    "argument": cs.argument,
                    "constant": cs.is_constant,
                }
                for cs in self.call_sites
            ],
        }


def first_arg_registers(arch: str | None) -> tuple[str, ...]:
    if not arch:
        return ("a0", "rdi", "r0", "x0")
    lowered = arch.lower()
    for key, regs in _ARG_REGS.items():
        if key in lowered:
            return regs
    return ("a0", "rdi", "r0", "x0")


def parse_disassembly_line(line: str) -> tuple[str, str, str] | None:
    match = _INSN_RE.match(line)
    if not match:
        return None
    return match.group("addr"), match.group("mnem").lower(), match.group("ops")

def extract_comment_string(line: str) -> str | None:
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
    window = _window_instructions(lines, call_index)
    call_addr, _, _ = parse_disassembly_line(window[-1]) or ("?", "", "")
    caller = next(
        (name for line in reversed(window) if (name := _caller_marker(line)) is not None),
        None,
    )
    if caller is not None:
        function = caller
        function_addr = parse_function_va(caller)
    else:
        function = _function_name_for_line(window[-1])
        function_addr = None
    evidence: list[str] = [line.strip() for line in window[-4:]]
    site = CallSite(
        function=function,
        address=call_addr,
        argument="<unresolved>",
        evidence=evidence,
        function_addr=function_addr,
    )

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
                if mnem.startswith("lui"):
                    partner = _find_addiu_pair(window, reg)
                    if partner is not None:
                        site.argument = partner
                        site.is_constant = True
                        return site
                if mnem.startswith(("move", "ori")) and reg in arg_regs:
                    site.argument = "<dynamic>"
                    return site
                site.argument = "<dynamic>"
                return site
    site.argument = "<unresolved>"
    return site


def _writes_register(mnem: str, ops: str, reg: str) -> bool:
    if not ops:
        return False
    dest = ops.split(",")[0].strip()
    return dest == reg


def _find_addiu_pair(window: list[str], reg: str) -> str | None:
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
    match = re.search(r"(?:sym|fcn)\.([A-Za-z0-9_.]+)", line)
    if match:
        return match.group(1)
    match = re.search(r";\s*([A-Za-z_][A-Za-z0-9_]*)\(", line)
    if match:
        return match.group(1)
    return "unknown"


def _caller_marker(line: str) -> str | None:
    match = re.search(r";\s*r2b-caller:\s*(?:sym\.|fcn\.)?([A-Za-z0-9_.]+)", line)
    return match.group(1) if match else None


def _dedupe_call_sites(call_sites: list[CallSite]) -> list[CallSite]:
    unique: dict[str, CallSite] = {}
    for site in call_sites:
        existing = unique.get(site.address)
        if existing is None:
            unique[site.address] = site
            continue
        if existing.function == "unknown" and site.function != "unknown":
            existing.function = site.function
        if existing.function_addr is None and site.function_addr:
            existing.function_addr = site.function_addr
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
                if references_import or _window_references(current[:-1], import_name):
                    verdict.call_sites.append(resolve_argument(current, len(current) - 1, arg_regs))
                    current = []
        verdict.call_sites = _dedupe_call_sites(verdict.call_sites)
        verdicts.append(verdict)
    return verdicts


def _window_references(window: list[str], import_name: str) -> bool:
    return any(import_name in line for line in window)
