"""Static Rust triage for stripped ARM ELF binaries.

No model and no radare2. Entry recovery, panic Location structs, and
source-path references come from the ELF bytes and a Capstone sweep.
Capstone is optional. Without it the toolchain fields still report.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

_RUST_COMMENT = re.compile(rb"rustc version ([0-9][^\s)]+)")
_RUSTC_COMMIT = re.compile(rb"/rustc/([0-9a-f]{40})/")
_RS_PATH = re.compile(rb"[\x20-\x7e]{4,200}\.rs")
_REGISTRY = re.compile(r"(?:^|/)([^/]+)-\d+\.\d+[^/]*/src(?:/|$)")
_STD_CRATES = frozenset(
    {
        "std",
        "core",
        "alloc",
        "proc_macro",
        "test",
        "stdarch",
        "panic_abort",
        "panic_unwind",
        "backtrace",
        "compiler_builtins",
    }
)
_RELATIVE = frozenset({1027, 23})  # R_AARCH64_RELATIVE, R_ARM_RELATIVE
_SKIP_SECTIONS = frozenset({".init", ".fini", ".plt", ".plt.sec", ".plt.got", ".iplt"})
_MAX_SWEEP = 8 * 1024 * 1024
_ZERO_REGS = frozenset({"wzr", "xzr", "zr"})


def classify_path(path: str) -> tuple[str, str | None]:
    """Classify a Rust source path as user, std, registry, or other.

    The crate name is the path component before ``/src/`` when that names a
    user crate. Registry and std paths do not yield a user crate.
    """
    text = path.replace("\\", "/").strip()
    low = text.lower()
    if "/rustc/" in low and "/library/" in low:
        return "std", None
    if "/rustlib/src/rust/library/" in low:
        return "std", None
    for crate in _STD_CRATES:
        if f"/library/{crate}/" in low:
            return "std", None
    if (
        "/cargo/registry/" in low
        or ".cargo/registry/" in low
        or "/registry/src/" in low
        or _REGISTRY.search(text)
    ):
        return "registry", None
    if text.endswith(".rs") and ("/src/" in text or text.startswith("src/")):
        crate = None
        if "/src/" in text:
            crate = text.split("/src/")[0].rstrip("/").split("/")[-1] or None
        if crate in _STD_CRATES:
            return "std", None
        return "user", crate
    return "other", None


@dataclass
class _Sec:
    name: str
    addr: int
    data: bytes
    flags: int

    @property
    def executable(self) -> bool:
        return (
            bool(self.flags & 0x4)
            and self.name not in _SKIP_SECTIONS
            and not self.name.startswith(".plt")
        )


@dataclass
class _Image:
    arch: str
    bits: int
    entry: int
    sections: list[_Sec]
    loads: list[tuple[int, bytes]]
    relocs: dict[int, int] = field(default_factory=dict)
    force_thumb: bool = False

    @property
    def ptr(self) -> int:
        return 8 if self.bits == 64 else 4

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1

    def read(self, va: int, size: int) -> bytes:
        for base, blob in self.loads:
            if base <= va < base + len(blob):
                off = va - base
                return blob[off : off + size]
        return b""

    def load_int(self, va: int, width: int) -> int | None:
        if width == self.ptr and va in self.relocs:
            return self.relocs[va] & self.mask
        raw = self.read(va, width)
        if len(raw) < width:
            return None
        return int.from_bytes(raw, "little")

    def section_at(self, va: int) -> _Sec | None:
        for sec in self.sections:
            if sec.addr <= va < sec.addr + len(sec.data):
                return sec
        return None

    def code_addr(self, value: int | None) -> int | None:
        if value is None:
            return None
        addr = value & ~1
        if self.arch == "aarch64" and value & 1:
            return None
        sec = self.section_at(addr)
        if sec is None or not sec.executable:
            return None
        if addr < sec.addr or addr >= sec.addr + len(sec.data):
            return None
        return addr

    def thumb_at(self, addr: int) -> bool:
        return self.force_thumb or self.arch == "arm" and addr in self._thumb

    def mark_thumb(self, value: int) -> int | None:
        code = self.code_addr(value)
        if code is None:
            return None
        if self.arch == "arm" and value & 1:
            self._thumb.add(code)
        return code

    _thumb: set[int] = field(default_factory=set)


def _open_image(path: Path) -> _Image | None:
    with path.open("rb") as handle:
        if handle.read(4) != b"\x7fELF":
            return None
        handle.seek(0)
        elf = ELFFile(handle)
        machine = elf.header["e_machine"]
        if machine == "EM_AARCH64":
            arch = "aarch64"
        elif machine == "EM_ARM":
            arch = "arm"
        else:
            return None
        bits = elf.elfclass
        sections: list[_Sec] = []
        for sec in elf.iter_sections():
            name = sec.name or ""
            if not name or sec["sh_type"] == "SHT_NOBITS":
                continue
            try:
                blob = sec.data()
            except Exception:
                continue
            sections.append(_Sec(name, int(sec["sh_addr"]), blob, int(sec["sh_flags"])))
        loads: list[tuple[int, bytes]] = []
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            loads.append((int(seg["p_vaddr"]), seg.data()))
        image = _Image(
            arch=arch,
            bits=bits,
            entry=int(elf.header["e_entry"]),
            sections=sections,
            loads=loads,
        )
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            rela = bool(sec.is_RELA())
            for rel in sec.iter_relocations():
                if int(rel["r_info_type"]) not in _RELATIVE:
                    continue
                slot = int(rel["r_offset"])
                if rela:
                    image.relocs[slot] = int(rel["r_addend"]) & image.mask
                else:
                    raw = image.read(slot, image.ptr)
                    if len(raw) == image.ptr:
                        image.relocs[slot] = int.from_bytes(raw, "little")
        return image


def _section_bytes(image: _Image, *names: str) -> list[tuple[str, int, bytes]]:
    found: list[tuple[str, int, bytes]] = []
    for sec in image.sections:
        if sec.name in names or any(sec.name.startswith(prefix) for prefix in names):
            found.append((sec.name, sec.addr, sec.data[:_MAX_SWEEP]))
    return found


def _toolchain(image: _Image) -> tuple[str | None, str | None, bool]:
    version = None
    commit = None
    rust = False
    blobs: list[bytes] = []
    for sec in image.sections:
        if sec.name in {".comment", ".rodata"} or sec.name.startswith((".rodata", ".data.rel.ro")):
            blobs.append(sec.data[:_MAX_SWEEP])
    for blob in blobs:
        if version is None:
            match = _RUST_COMMENT.search(blob)
            if match:
                version = match.group(1).decode("ascii", "replace")
                rust = True
        if commit is None:
            match = _RUSTC_COMMIT.search(blob)
            if match:
                commit = match.group(1).decode("ascii")
                rust = True
        if b"rustc version" in blob or b"/rustc/" in blob:
            rust = True
    return version, commit, rust


def _paths_and_locations(
    image: _Image,
) -> tuple[dict[int, tuple[str, str | None]], list[str]]:
    """Map data VAs to path class, and collect user crate names."""
    interesting: dict[int, tuple[str, str | None]] = {}
    crates: set[str] = set()

    def add_path(va: int, text: str) -> None:
        kind, crate = classify_path(text)
        if kind == "other":
            return
        interesting[va] = (kind, crate)
        if kind == "user" and crate:
            crates.add(crate)

    for _name, base, blob in _section_bytes(image, ".rodata", ".data.rel.ro", ".data"):
        for match in _RS_PATH.finditer(blob):
            add_path(base + match.start(), match.group().decode("ascii", "replace"))
        step = image.ptr
        rec = 24 if step == 8 else 16
        limit = min(len(blob), _MAX_SWEEP)
        index = 0
        while index + rec <= limit:
            ptr = image.load_int(base + index, step)
            if ptr is None:
                index += step
                continue
            if step == 8:
                length = int.from_bytes(blob[index + 8 : index + 16], "little")
                line = int.from_bytes(blob[index + 16 : index + 20], "little")
                col = int.from_bytes(blob[index + 20 : index + 24], "little")
            else:
                length = int.from_bytes(blob[index + 4 : index + 8], "little")
                line = int.from_bytes(blob[index + 8 : index + 12], "little")
                col = int.from_bytes(blob[index + 12 : index + 16], "little")
            if not (1 <= length <= 400 and 1 <= line <= 1_000_000 and 0 <= col <= 10_000):
                index += step
                continue
            raw = image.read(ptr, length)
            if len(raw) != length or not raw.endswith(b".rs"):
                index += step
                continue
            if any(byte < 0x20 or byte > 0x7E for byte in raw):
                index += step
                continue
            add_path(ptr, raw.decode("ascii"))
            interesting.setdefault(base + index, interesting.get(ptr, ("other", None)))
            if interesting.get(base + index, ("other", None))[0] == "other":
                interesting.pop(base + index, None)
            else:
                # The Location object itself is what code usually addresses.
                kind, crate = classify_path(raw.decode("ascii"))
                if kind != "other":
                    interesting[base + index] = (kind, crate)
            index += rec
    return interesting, sorted(crates)


def _split_ops(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [part for part in parts if part]


def _imm(token: str) -> int | None:
    text = token.strip()
    if text.startswith("#"):
        text = text[1:]
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _parse_mem(token: str) -> tuple[str, str | None, int] | None:
    if "[" not in token:
        return None
    inner = token[token.index("[") + 1 : token.index("]")]
    bits = [bit.strip() for bit in inner.split(",") if bit.strip()]
    if not bits:
        return None
    base = bits[0]
    index = None
    disp = 0
    if len(bits) > 1:
        if bits[1].startswith("#"):
            disp = _imm(bits[1]) or 0
        else:
            index = bits[1]
            if len(bits) > 2 and "#" in bits[2]:
                disp = _imm(bits[2][bits[2].index("#") :]) or 0
    return base, index, disp


def _canon(name: str, aarch64: bool) -> str:
    token = name.strip().lower()
    if aarch64 and len(token) >= 2 and token[0] == "w" and token[1].isdigit():
        return "x" + token[1:]
    return token


class _Machine:
    def __init__(self, image: _Image, thumb: bool) -> None:
        self.image = image
        self.thumb = thumb
        self.aarch64 = image.arch == "aarch64"
        self.regs: dict[str, tuple[str, int]] = {}
        self.stack: dict[int, tuple[str, int]] = {}
        self.sp = 0

    def reset(self) -> None:
        self.regs.clear()
        self.stack.clear()
        self.sp = 0

    def _pc(self, addr: int) -> int:
        if self.aarch64:
            return addr
        if self.thumb:
            return (addr + 4) & ~3
        return addr + 8

    def _val(self, token: str, pc: int) -> tuple[str, int] | None:
        if token.startswith("#"):
            imm = _imm(token)
            return None if imm is None else ("imm", imm)
        key = _canon(token, self.aarch64)
        if key == "pc":
            return ("imm", pc)
        if key == "sp":
            return ("stk", self.sp)
        if key in _ZERO_REGS:
            return ("imm", 0)
        return self.regs.get(key)

    def _set(self, token: str, value: tuple[str, int] | None) -> None:
        key = _canon(token, self.aarch64)
        if key in _ZERO_REGS or key in {"pc", "sp"}:
            return
        if value is None:
            self.regs.pop(key, None)
        else:
            self.regs[key] = value

    def _combine(
        self, left: tuple[str, int] | None, right: tuple[str, int] | None, sub: bool
    ) -> tuple[str, int] | None:
        if left is None or right is None:
            return None
        sign = -1 if sub else 1
        if left[0] == "imm" and right[0] == "imm":
            return ("imm", (left[1] + sign * right[1]) & self.image.mask)
        if not sub and left[0] == "stk" and right[0] == "imm":
            return ("stk", left[1] + right[1])
        if not sub and right[0] == "stk" and left[0] == "imm":
            return ("stk", right[1] + left[1])
        return None

    def call_arg(self) -> int | None:
        key = "x0" if self.aarch64 else "r0"
        value = self.regs.get(key)
        if value is None:
            return None
        if value[0] == "stk":
            value = self.stack.get(value[1])
        if value is None or value[0] != "imm":
            return None
        return value[1]

    def feed(self, insn: Any) -> tuple[list[int], list[int], bool]:
        """Return loaded/computed values, referenced addresses, and whether this calls."""
        values: list[int] = []
        refs: list[int] = []
        base = insn.mnemonic.split(".")[0]
        ops = _split_ops(insn.op_str)
        pc = self._pc(insn.address)

        if base in {"push", "pop"}:
            count = len(re.findall(r"[A-Za-z][A-Za-z0-9]*", insn.op_str)) or 1
            self.sp += (-4 if base == "push" else 4) * count
            return values, refs, False
        if base == "sub" and ops and _canon(ops[0], self.aarch64) == "sp":
            imm = _imm(ops[-1]) if ops[-1].startswith("#") else None
            if imm is not None:
                self.sp -= imm
            return values, refs, False
        if (
            base == "add"
            and ops
            and _canon(ops[0], self.aarch64) == "sp"
            and ops[-1].startswith("#")
        ):
            imm = _imm(ops[-1])
            if imm is not None:
                self.sp += imm
            return values, refs, False
        if base in {"bl", "blx"}:
            return values, refs, True
        if base == "adrp" and len(ops) >= 2:
            imm = _imm(ops[1])
            if imm is not None:
                self._set(ops[0], ("imm", imm & self.image.mask))
            return values, refs, False
        if base == "adr" and len(ops) >= 2:
            disp = _imm(ops[1])
            if disp is not None:
                target = disp if self.aarch64 and disp > 0xFFFF else (pc + disp) & self.image.mask
                # AArch64 ADR immediates from Capstone are absolute. ARM/Thumb are displacements.
                if not self.aarch64:
                    target = (pc + disp) & self.image.mask
                self._set(ops[0], ("imm", target))
                values.append(target)
            return values, refs, False
        if base in {"add", "sub"} and ops:
            if len(ops) == 2:
                result = self._combine(self._val(ops[0], pc), self._val(ops[1], pc), base == "sub")
            else:
                result = self._combine(self._val(ops[1], pc), self._val(ops[2], pc), base == "sub")
            self._set(ops[0], result)
            if result and result[0] == "imm":
                values.append(result[1])
            return values, refs, False
        if base in {"mov", "movw", "movz"} and len(ops) >= 2:
            if base == "movw":
                imm = _imm(ops[1])
                if imm is not None:
                    self._set(ops[0], ("imm", imm & 0xFFFF))
                return values, refs, False
            if base == "movz":
                imm = _imm(ops[1]) or 0
                shift = 0
                if len(ops) >= 3 and "#" in ops[2]:
                    shift = _imm(ops[2][ops[2].index("#") :]) or 0
                value = (imm << shift) & self.image.mask
                self._set(ops[0], ("imm", value))
                return values, refs, False
            value = self._val(ops[1], pc)
            self._set(ops[0], value)
            if value and value[0] == "imm":
                values.append(value[1])
            return values, refs, False
        if base == "movt" and len(ops) >= 2:
            imm = _imm(ops[1])
            if imm is not None:
                old = self._val(ops[0], pc)
                low = old[1] if old and old[0] == "imm" else 0
                value = (low & 0xFFFF) | ((imm & 0xFFFF) << 16)
                self._set(ops[0], ("imm", value))
                values.append(value)
            return values, refs, False
        if base == "movk" and len(ops) >= 2:
            imm = _imm(ops[1]) or 0
            shift = 0
            if len(ops) >= 3 and "#" in ops[2]:
                shift = _imm(ops[2][ops[2].index("#") :]) or 0
            old = self._val(ops[0], pc)
            current = old[1] if old and old[0] == "imm" else 0
            mask = 0xFFFF << shift
            value = (current & ~mask) | ((imm & 0xFFFF) << shift)
            self._set(ops[0], ("imm", value & self.image.mask))
            values.append(value & self.image.mask)
            return values, refs, False
        if base in {"ldr", "ldur"} and len(ops) >= 2:
            mem = _parse_mem(ops[1])
            if mem is None:
                self._set(ops[0], None)
                return values, refs, False
            base_r, index, disp = mem
            base_v = self._val(base_r, pc)
            if base_v and base_v[0] == "stk" and index is None:
                slot = self.stack.get(base_v[1] + disp)
                self._set(ops[0], slot)
                return values, refs, False
            addr = None
            if base_v and base_v[0] == "imm":
                addr = base_v[1] + disp
                if index is not None:
                    extra = self._val(index, pc)
                    if extra is None or extra[0] != "imm":
                        addr = None
                    else:
                        addr += extra[1]
            if addr is None:
                self._set(ops[0], None)
                return values, refs, False
            addr &= self.image.mask
            refs.append(addr)
            dest = _canon(ops[0], self.aarch64)
            width = 8 if dest.startswith("x") else 4
            loaded = self.image.load_int(addr, width)
            if loaded is None:
                self._set(ops[0], None)
            else:
                self._set(ops[0], ("imm", loaded))
                values.append(loaded)
            return values, refs, False
        if base in {"str", "stur"} and len(ops) >= 2:
            mem = _parse_mem(ops[1])
            if mem is not None:
                base_r, _index, disp = mem
                base_v = self._val(base_r, pc)
                src = self._val(ops[0], pc)
                if base_v and base_v[0] == "stk" and src is not None:
                    self.stack[base_v[1] + disp] = src
            return values, refs, False
        if base in {"stp", "ldp"} and ops:
            # Clobber so a stale address is not reused. The lang_start slot is an STR.
            if base == "ldp":
                self._set(ops[0], None)
                if len(ops) > 1:
                    self._set(ops[1], None)
            return values, refs, False
        return values, refs, False


def _capstone():
    try:
        from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB, Cs
    except ImportError:
        return None
    return Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB


def _md_for(image: _Image, thumb: bool) -> Any | None:
    loaded = _capstone()
    if loaded is None:
        return None
    cs, arch_arm, arch_arm64, mode_arm, mode_thumb = loaded
    if image.arch == "aarch64":
        md = cs(arch_arm64, mode_arm)
    elif thumb:
        md = cs(arch_arm, mode_thumb)
    else:
        md = cs(arch_arm, mode_arm)
    md.detail = False
    return md


def _iter_insns(image: _Image, start: int, thumb: bool, max_bytes: int):
    md = _md_for(image, thumb)
    if md is None:
        return
    sec = image.section_at(start)
    if sec is None:
        return
    off = start - sec.addr
    blob = sec.data
    end = min(len(blob), off + max_bytes)
    step = 2 if thumb else 4
    while off + step <= end:
        window = blob[off : min(end, off + 4096)]
        insns = list(md.disasm(window, sec.addr + off))
        if not insns:
            off += step
            continue
        for insn in insns:
            if insn.address >= sec.addr + end:
                return
            yield insn
        nxt = insns[-1].address + insns[-1].size - sec.addr
        off = nxt if nxt > off else off + step


def _branch_target(insn: Any) -> int | None:
    if insn.op_str.startswith("#"):
        return _imm(insn.op_str)
    return None


def _is_prologue(insn: Any) -> bool:
    mnem = insn.mnemonic
    text = insn.op_str
    if mnem in {"paciasp", "pacibsp"}:
        return True
    if mnem == "bti" and text.strip() in {"c", "j", "jc"}:
        return True
    if mnem == "push" and re.search(r"\b(lr|pc)\b", text):
        return True
    if mnem == "stp" and "x29" in text and "x30" in text and ("!" in text or "#-" in text):
        return True
    return False


def _is_return(insn: Any) -> bool:
    return (
        insn.mnemonic in {"ret", "retaa", "retab", "autiasp", "autibsp", "bx"}
        or insn.mnemonic == "b"
    )


def _recover_libc_main(image: _Image) -> int | None:
    entry = image.entry
    thumb = image.arch == "arm" and bool(entry & 1)
    start = entry & ~1
    machine = _Machine(image, thumb)
    for count, insn in enumerate(_iter_insns(image, start, thumb, 0x80)):
        if count > 40:
            break
        _values, _refs, is_call = machine.feed(insn)
        if not is_call:
            continue
        return image.mark_thumb(machine.call_arg())
    return None


def _recover_user_main(image: _Image, c_main: int) -> int | None:
    thumb = image.thumb_at(c_main)
    machine = _Machine(image, thumb)
    seen: list[int] = []
    for count, insn in enumerate(_iter_insns(image, c_main, thumb, 0x400)):
        if count >= 120:
            break
        values, _refs, is_call = machine.feed(insn)
        for value in values:
            code = image.mark_thumb(value)
            if code is not None and code != c_main:
                seen.append(code)
        if is_call and seen:
            picked = image.mark_thumb(machine.call_arg())
            if picked and picked != c_main:
                return picked
            return seen[0]
    for code in seen:
        if code != c_main:
            return image.mark_thumb(code) or code
    return None


def _cortex_reset(image: _Image) -> tuple[int, int] | None:
    if image.arch != "arm":
        return None
    raw = image.read(0, 8)
    if len(raw) < 8 or raw.startswith(b"\x7fELF"):
        return None
    sp, reset = struct.unpack_from("<II", raw)
    if sp % 8 or sp < 0x20000000 or not reset & 1:
        return None
    code = image.code_addr(reset)
    if code is None:
        return None
    if image.entry and (image.entry | 1) != (reset | 1):
        return None
    return sp, code


def _unwrap_trampoline(image: _Image, addr: int) -> int:
    calls: list[int] = []
    for index, insn in enumerate(_iter_insns(image, addr, True, 0x20)):
        if index > 0 and _is_prologue(insn):
            return calls[0] if len(calls) == 1 else addr
        if insn.mnemonic == "bl":
            target = _branch_target(insn)
            code = image.code_addr(target) if target is not None else None
            if code is not None:
                calls.append(code)
        if insn.mnemonic in {"udf", "bx", "pop"} or insn.mnemonic == "b":
            if len(calls) == 1 and index <= 6:
                return calls[0]
            return addr
        if index >= 8:
            break
    return addr


def _recover_cortex(image: _Image) -> tuple[list[int], int | None]:
    found = _cortex_reset(image)
    if found is None:
        return [], None
    _sp, reset = found
    image.force_thumb = True
    image.mark_thumb(reset | 1)
    last: int | None = None
    for insn in _iter_insns(image, reset, True, 0x200):
        if insn.mnemonic in {"udf", "bkpt"}:
            break
        if insn.mnemonic == "bl":
            target = _branch_target(insn)
            code = image.code_addr(target) if target is not None else None
            if code is not None:
                last = code
                image.mark_thumb(code | 1)
    if last is None:
        return [reset], None
    user = _unwrap_trampoline(image, last)
    image.mark_thumb(user | 1)
    chain = [reset]
    if last != reset:
        chain.append(last)
    if user not in chain:
        chain.append(user)
    return chain, user


def _is_thunk(image: _Image, addr: int) -> bool:
    thumb = image.thumb_at(addr)
    insns = []
    for insn in _iter_insns(image, addr, thumb, 16):
        insns.append(insn)
        if len(insns) >= 3:
            break
    body = [insn for insn in insns if insn.mnemonic not in {"paciasp", "pacibsp", "bti", "nop"}]
    if not body:
        return True
    return body[0].mnemonic in {"b", "br", "bx", "ret", "retaa", "retab"}


def _snippet(image: _Image, addr: int) -> str:
    lines: list[str] = []
    for insn in _iter_insns(image, addr, image.thumb_at(addr), 32):
        lines.append(f"{insn.address:#x}  {insn.mnemonic} {insn.op_str}".rstrip())
        if len(lines) >= 8:
            break
    return "\n".join(lines) or f"{addr:#x}"


def _callees(image: _Image, start: int) -> list[int]:
    thumb = image.thumb_at(start)
    machine = _Machine(image, thumb)
    found: list[int] = []
    for insn in _iter_insns(image, start, thumb, 0x800):
        if insn.address != start and insn.address > start + 4 and _is_prologue(insn):
            break
        values, _refs, is_call = machine.feed(insn)
        if is_call:
            target = _branch_target(insn)
            code = image.mark_thumb(target) if target is not None else None
            if code is not None and code != start:
                found.append(code)
            continue
        for value in values:
            code = image.code_addr(value)
            if code is not None and code != start and abs(code - start) < 0x10000:
                # Only keep materialized targets that themselves look like functions.
                head = next(_iter_insns(image, code, image.thumb_at(code), 4), None)
                if (
                    head is not None
                    and head.address == code
                    and (_is_prologue(head) or head.mnemonic in {"sub", "stp", "push"})
                ):
                    found.append(code)
    ordered: list[int] = []
    for addr in found:
        if addr not in ordered:
            ordered.append(addr)
    return ordered


def _sweep_xrefs(
    image: _Image, interesting: dict[int, tuple[str, str | None]]
) -> tuple[dict[int, list[int]], list[int]]:
    """Map code addresses to interesting data VAs, and collect prologue starts."""
    if not interesting or _capstone() is None:
        return {}, []
    refs: dict[int, list[int]] = {}
    starts: list[int] = []
    keys = set(interesting)
    for sec in image.sections:
        if not sec.executable or len(sec.data) > _MAX_SWEEP:
            continue
        thumb = image.force_thumb
        machine = _Machine(image, thumb)
        # ARM Linux user code is A32. Thumb entry stubs are decoded on their own.
        if image.arch == "arm" and not image.force_thumb:
            thumb = False
            machine = _Machine(image, False)
        for insn in _iter_insns(image, sec.addr, thumb, len(sec.data)):
            if _is_prologue(insn) or insn.mnemonic in {"ret", "retaa", "retab"}:
                machine.reset()
            if _is_prologue(insn):
                starts.append(insn.address)
            if insn.mnemonic in {"bl", "blx"}:
                target = _branch_target(insn)
                code = image.code_addr(target) if target is not None else None
                if code is not None:
                    starts.append(code)
            values, mems, _call = machine.feed(insn)
            for value in values + mems:
                if value in keys:
                    refs.setdefault(insn.address, []).append(value)
    starts = sorted(set(starts))
    return refs, starts


def _snap(starts: list[int], addr: int) -> int:
    if not starts:
        return addr
    # Greatest start at or before addr, within 16KiB.
    lo = 0
    hi = len(starts)
    while lo < hi:
        mid = (lo + hi) // 2
        if starts[mid] <= addr:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return addr
    start = starts[lo - 1]
    if addr - start > 0x4000:
        return addr
    return start


def _hex(addr: int) -> str:
    return hex(addr)


def analyze_rust(path: str | Path) -> dict[str, Any] | None:
    """Return Rust triage for an ELF, or None when the file is not Rust ARM."""
    file_path = Path(path)
    if not file_path.is_file():
        return None
    try:
        image = _open_image(file_path)
    except Exception:
        return None
    if image is None:
        return None
    version, commit, marked = _toolchain(image)
    try:
        interesting, crates = _paths_and_locations(image)
    except Exception:
        interesting, crates = {}, []
    if any(kind == "user" or kind == "std" for kind, _crate in interesting.values()):
        marked = True
    if not marked and version is None and commit is None:
        return None

    chain: list[int] = []
    user_main: int | None = None
    c_main: int | None = None
    if _capstone() is not None:
        cortex_chain, cortex_main = _recover_cortex(image)
        if cortex_main is not None:
            chain = cortex_chain
            user_main = cortex_main
        else:
            c_main = _recover_libc_main(image)
            entry = image.entry & ~1
            if c_main is not None:
                user_main = _recover_user_main(image, c_main)
            if image.arch == "arm" and image.entry & 1:
                image.mark_thumb(image.entry)
            chain = [addr for addr in (entry, c_main, user_main) if addr is not None]

    xrefs, starts = _sweep_xrefs(image, interesting)
    if user_main is not None:
        starts.append(user_main)
        starts = sorted(set(starts))

    # Score functions by the paths they reference.
    ref_user: dict[int, int] = {}
    ref_std: dict[int, int] = {}
    for site, vas in xrefs.items():
        func = _snap(starts, site)
        for va in vas:
            kind, _crate = interesting.get(va, ("other", None))
            if kind == "user":
                ref_user[func] = ref_user.get(func, 0) + 1
            elif kind in {"std", "registry"}:
                ref_std[func] = ref_std.get(func, 0) + 1

    ranked: dict[int, tuple[int, str, str]] = {}

    def add(addr: int | None, score: int, role: str, why: str) -> None:
        if addr is None:
            return
        current = ranked.get(addr)
        if current is None or score > current[0]:
            ranked[addr] = (score, role, why)

    if user_main is not None:
        how = (
            "Reset vector reaches this function through the cortex-m-rt main trampoline."
            if image.force_thumb
            else "C main loads this pointer and passes it to lang_start."
        )
        add(user_main, 240, "user_main", how)
    for func, count in ref_user.items():
        std = ref_std.get(func, 0)
        if count == 0 or std > count:
            continue
        add(
            func,
            210 + min(count, 8) - min(std, 4),
            "user",
            "Code references a user-crate source path.",
        )
    if user_main is not None:
        for index, callee in enumerate(_callees(image, user_main)):
            snapped = _snap(starts, callee)
            if snapped == user_main or _is_thunk(image, snapped):
                continue
            user_n = ref_user.get(snapped, 0) or ref_user.get(callee, 0)
            std_n = ref_std.get(snapped, 0) or ref_std.get(callee, 0)
            if std_n > user_n and user_n == 0:
                continue
            if abs(snapped - user_main) > 0x6000 and user_n == 0:
                continue
            add(
                snapped,
                190 - min(index, 20) + min(user_n, 4),
                "user",
                "Direct call or function pointer from user main.",
            )

    functions = []
    for addr, (score, role, why) in sorted(ranked.items(), key=lambda item: (-item[1][0], item[0])):
        if len(functions) >= 12:
            break
        functions.append(
            {
                "addr": _hex(addr),
                "score": score,
                "role": role,
                "title": "Rust user main" if role == "user_main" else "Rust user function",
                "why": why,
                "snippet": _snippet(image, addr),
            }
        )
    reported_main = None
    for func in functions:
        if func["role"] == "user_main":
            reported_main = func["addr"]
            break
    return {
        "is_rust": True,
        "rustc_version": version,
        "rustc_commit": commit,
        "user_crates": crates,
        "user_main": reported_main,
        "entry_chain": [_hex(addr) for addr in chain],
        "functions": functions,
    }
