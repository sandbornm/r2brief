"""Static Rust triage over synthetic ELF bytes. No eval corpus."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from r2b.analysis.briefing import build_briefing
from r2b.analysis.rust import (
    _Image,
    _Sec,
    _callees,
    _cortex_reset,
    _snap,
    _sweep_xrefs,
    analyze_rust,
    classify_path,
)

VA = 0x10000
TEXT_OFF = 0x100
GOT_OFF = 0x300
RO_OFF = 0x400
ENTRY = VA + TEXT_OFF
C_MAIN = ENTRY + 0x20
LANG = ENTRY + 0x40
USER = ENTRY + 0x80
REF = ENTRY + 0xE0
GOT = VA + GOT_OFF
LOC = VA + RO_OFF
USER_PATH = b"demo_app/src/main.rs"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def test_classify_path_user_std_and_registry():
    assert classify_path("src/main.rs") == ("user", None)
    assert classify_path("demo_app/src/main.rs") == ("user", "demo_app")
    assert classify_path(r"crate\src\lib.rs") == ("user", "crate")
    assert classify_path(f"/rustc/{COMMIT}/library/core/src/panic.rs") == ("std", None)
    assert classify_path("/rustlib/src/rust/library/std/src/sys/mod.rs") == ("std", None)
    assert classify_path("/library/alloc/src/raw_vec.rs") == ("std", None)
    assert classify_path("core/src/panicking.rs") == ("std", None)
    assert classify_path("/cargo/registry/src/index/serde-1.0.210/src/lib.rs") == ("registry", None)
    assert classify_path(".cargo/registry/src/index/libc-0.2.155/src/lib.rs") == ("registry", None)
    assert classify_path("/registry/src/github.com-1ecc6299db9ec823/foo-0.1.0/src/lib.rs") == (
        "registry",
        None,
    )
    assert classify_path("README") == ("other", None)
    assert classify_path("/build/proj/src/main.rs") == ("user", "proj")
    assert classify_path("/home/user/app-1.0/src/main.rs") == ("user", "app-1.0")


def _adrp(rd: int, pc: int, page: int) -> bytes:
    delta = ((page - (pc & ~0xFFF)) >> 12) & ((1 << 21) - 1)
    immlo = delta & 3
    immhi = (delta >> 2) & 0x7FFFF
    word = (1 << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | rd
    return struct.pack("<I", word)


def _add(rd: int, rn: int, imm: int) -> bytes:
    return struct.pack("<I", 0x91000000 | (imm << 10) | (rn << 5) | rd)


def _ldr(rt: int, rn: int, byte_off: int) -> bytes:
    return struct.pack("<I", 0xF9400000 | ((byte_off // 8) << 10) | (rn << 5) | rt)


def _bl(pc: int, target: int) -> bytes:
    imm = (target - pc) >> 2
    return struct.pack("<I", 0x94000000 | (imm & 0x3FFFFFF))


def _u32(word: int) -> bytes:
    return struct.pack("<I", word)


NOP = _u32(0xD503201F)
PAC = _u32(0xD503233F)
RET = _u32(0xD65F03C0)


def _text() -> bytes:
    blob = bytearray(NOP * (0x100 // 4))
    blob[0:12] = _adrp(0, ENTRY, GOT & ~0xFFF) + _ldr(0, 0, GOT & 0xFFF) + _bl(ENTRY + 8, C_MAIN)
    blob[0x1C:0x20] = RET
    blob[0x20:0x2C] = (
        _adrp(0, C_MAIN, USER & ~0xFFF) + _add(0, 0, USER & 0xFFF) + _bl(C_MAIN + 8, LANG)
    )
    blob[0x2C:0x30] = RET
    blob[0x40:0x44] = RET
    blob[0x80:0x84] = PAC
    blob[0xC0:0xC4] = RET
    blob[0xE0:0xF0] = PAC + _adrp(1, REF, LOC & ~0xFFF) + _add(1, 1, LOC & 0xFFF) + RET
    return bytes(blob)


def _rodata() -> bytes:
    std = f"/rustc/{COMMIT}/library/core/src/panic.rs".encode()
    record = struct.pack("<QQII", LOC + 0x20, len(USER_PATH), 12, 1)
    return record + b"\x00" * (0x20 - len(record)) + USER_PATH + b"\x00" + std + b"\x00"


def _comment() -> bytes:
    return b"rustc version 1.80.0 (short 2024-01-01)\x00"


def _elf64(path: Path, text: bytes, rodata: bytes, comment: bytes, rela: bytes) -> None:
    names = ["", ".text", ".data.rel.ro", ".rodata", ".comment", ".rela.dyn", ".shstrtab"]
    strtab = b"\x00".join(name.encode() for name in names) + b"\x00"
    name_off = {}
    cursor = 0
    for name in names:
        name_off[name] = cursor
        cursor += len(name) + 1
    comment_off = RO_OFF + len(rodata)
    rela_off = comment_off + len(comment)
    str_off = rela_off + len(rela)
    shoff = str_off + len(strtab)
    shnum = len(names)
    buf = bytearray(shoff + 64 * shnum)
    buf[TEXT_OFF : TEXT_OFF + len(text)] = text
    buf[GOT_OFF : GOT_OFF + 8] = b"\x00" * 8
    buf[RO_OFF : RO_OFF + len(rodata)] = rodata
    buf[comment_off : comment_off + len(comment)] = comment
    buf[rela_off : rela_off + len(rela)] = rela
    buf[str_off : str_off + len(strtab)] = strtab

    def shdr(
        name: str, typ: int, flags: int, addr: int, off: int, size: int, entsize: int = 0
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", name_off[name], typ, flags, addr, off, size, 0, 0, 1, entsize
        )

    sections = [
        shdr("", 0, 0, 0, 0, 0),
        shdr(".text", 1, 6, ENTRY, TEXT_OFF, len(text)),
        shdr(".data.rel.ro", 1, 2, GOT, GOT_OFF, 8),
        shdr(".rodata", 1, 2, LOC, RO_OFF, len(rodata)),
        shdr(".comment", 1, 0, 0, comment_off, len(comment)),
        shdr(".rela.dyn", 4, 0, 0, rela_off, len(rela), 24),
        shdr(".shstrtab", 3, 0, 0, str_off, len(strtab)),
    ]
    for index, raw in enumerate(sections):
        start = shoff + index * 64
        buf[start : start + 64] = raw
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        183,
        1,
        ENTRY,
        64,
        shoff,
        0,
        64,
        56,
        1,
        64,
        shnum,
        shnum - 1,
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, VA, VA, len(buf), len(buf), 0x1000)
    buf[0:64] = ehdr
    buf[64:120] = phdr
    path.write_bytes(buf)


def _aarch64_rust(path: Path) -> None:
    rela = struct.pack("<QQq", GOT, 1027, C_MAIN)
    _elf64(path, _text(), _rodata(), _comment(), rela)


def test_aarch64_recovers_user_main_and_toolchain(tmp_path: Path):
    pytest.importorskip("capstone")
    binary = tmp_path / "rust-aarch64"
    _aarch64_rust(binary)
    info = analyze_rust(binary)
    assert info is not None
    assert info["is_rust"] is True
    assert info["rustc_version"] == "1.80.0"
    assert info["rustc_commit"] == COMMIT
    assert info["user_crates"] == ["demo_app"]
    assert info["user_main"] == hex(USER)
    assert info["entry_chain"] == [hex(ENTRY), hex(C_MAIN), hex(USER)]
    assert info["functions"][0]["role"] == "user_main"
    assert info["functions"][0]["addr"] == hex(USER)
    roles = [(item["addr"], item["role"]) for item in info["functions"]]
    assert (hex(REF), "user") in roles


def test_toolchain_without_capstone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binary = tmp_path / "rust-aarch64"
    _aarch64_rust(binary)
    monkeypatch.setattr("r2b.analysis.rust._capstone", lambda: None)
    info = analyze_rust(binary)
    assert info is not None
    assert info["rustc_version"] == "1.80.0"
    assert info["rustc_commit"] == COMMIT
    assert info["user_main"] is None
    assert info["functions"] == []


def test_non_rust_and_non_arm_are_ignored(tmp_path: Path):
    plain = tmp_path / "note"
    plain.write_bytes(b"this is not an elf")
    assert analyze_rust(plain) is None
    assert analyze_rust(tmp_path / "missing") is None
    binary = tmp_path / "not-rust"
    _elf64(binary, NOP * 4, b"hello\x00", b"GCC: (GNU) 12\x00", b"")
    assert analyze_rust(binary) is None
    x86 = tmp_path / "x86"
    _aarch64_rust(x86)
    blob = bytearray(x86.read_bytes())
    blob[18:20] = struct.pack("<H", 62)  # EM_X86_64
    x86.write_bytes(blob)
    assert analyze_rust(x86) is None


def test_elf_magic_is_not_a_cortex_vector():
    class _Fake:
        arch = "arm"
        entry = 0

        def read(self, _va: int, size: int) -> bytes:
            return b"\x7fELF\x01\x01\x01\x00"[:size]

    assert _cortex_reset(_Fake()) is None  # type: ignore[arg-type]


def _thumb_bl(pc: int, target: int) -> bytes:
    offset = target - (pc + 4)
    s = (offset >> 24) & 1
    i1 = (offset >> 23) & 1
    i2 = (offset >> 22) & 1
    imm10 = (offset >> 12) & 0x3FF
    imm11 = (offset >> 1) & 0x7FF
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0xD000 | (j1 << 13) | (1 << 12) | (j2 << 11) | imm11
    return struct.pack("<HH", hw1, hw2)


def _elf32(path: Path) -> None:
    load_off = 0x100
    text_va = 0x100
    tramp = 0x110
    user = 0x120
    ro_va = 0x200
    text = bytearray(b"\x00" * 0x40)
    text[0:6] = _thumb_bl(text_va, tramp) + b"\x00\xde"
    text[0x10:0x18] = b"\x80\xb5\x6f\x46" + _thumb_bl(tramp + 4, user) + b"\x70\x47"
    text[0x20:0x22] = b"\x70\x47"
    path_s = b"fw_uart/src/main.rs"
    record = struct.pack("<IIII", ro_va + 16, len(path_s), 4, 2)
    ro = record + path_s + b"\x00" + f"/rustc/{COMMIT}/".encode()
    comment = b"rustc version 1.80.0 (aaaaaaaa 2024-01-01)\x00"
    names = ["", ".text", ".rodata", ".comment", ".shstrtab"]
    strtab = b"\x00".join(name.encode() for name in names) + b"\x00"
    name_off: dict[str, int] = {}
    cursor = 0
    for name in names:
        name_off[name] = cursor
        cursor += len(name) + 1
    ro_off = load_off + ro_va
    comment_off = ro_off + len(ro)
    str_off = comment_off + len(comment)
    shoff = str_off + len(strtab)
    shnum = len(names)
    buf = bytearray(shoff + 40 * shnum)
    buf[load_off : load_off + 8] = struct.pack("<II", 0x20004000, text_va | 1)
    buf[load_off + text_va : load_off + text_va + len(text)] = text
    buf[ro_off : ro_off + len(ro)] = ro
    buf[comment_off : comment_off + len(comment)] = comment
    buf[str_off : str_off + len(strtab)] = strtab

    def shdr(name: str, typ: int, flags: int, addr: int, off: int, size: int) -> bytes:
        return struct.pack("<IIIIIIIIII", name_off[name], typ, flags, addr, off, size, 0, 0, 1, 0)

    sections = [
        shdr("", 0, 0, 0, 0, 0),
        shdr(".text", 1, 6, text_va, load_off + text_va, len(text)),
        shdr(".rodata", 1, 2, ro_va, ro_off, len(ro)),
        shdr(".comment", 1, 0, 0, comment_off, len(comment)),
        shdr(".shstrtab", 3, 0, 0, str_off, len(strtab)),
    ]
    for index, raw in enumerate(sections):
        start = shoff + index * 40
        buf[start : start + 40] = raw
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        2,
        40,
        1,
        text_va | 1,
        52,
        shoff,
        0x05000000,
        52,
        32,
        1,
        40,
        shnum,
        shnum - 1,
    )
    filesz = len(buf) - load_off
    phdr = struct.pack("<IIIIIIII", 1, load_off, 0, 0, filesz, filesz, 5, 4)
    buf[0:52] = ehdr
    buf[52:84] = phdr
    path.write_bytes(buf)


def _arm_bl(pc: int, target: int) -> bytes:
    imm = ((target - (pc + 8)) >> 2) & 0xFFFFFF
    return struct.pack("<I", 0xEB000000 | imm)


def _arm_linux(path: Path) -> None:
    """PIE ARM ELF. Entry is ARM state and loads C main through an SHT_REL slot."""
    va = 0x8000
    text_off = 0x100
    entry = va + text_off
    c_main = entry + 0x20
    user = entry + 0x40
    slot = entry + 12
    text = bytearray(b"\x00" * 0x60)
    text[0:8] = struct.pack("<I", 0xE59F0004) + _arm_bl(entry + 4, c_main)
    text[12:16] = struct.pack("<I", c_main)
    text[0x20:0x28] = struct.pack("<I", 0xE59F0004) + _arm_bl(c_main + 4, c_main + 0x10)
    text[0x2C:0x30] = struct.pack("<I", user)
    text[0x40:0x44] = struct.pack("<I", 0xE12FFF1E)  # bx lr
    rela = struct.pack("<II", slot, 23)
    comment = _comment()
    names = ["", ".text", ".comment", ".rel.dyn", ".shstrtab"]
    strtab = b"\x00".join(name.encode() for name in names) + b"\x00"
    name_off: dict[str, int] = {}
    cursor = 0
    for name in names:
        name_off[name] = cursor
        cursor += len(name) + 1
    comment_off = text_off + len(text)
    rel_off = comment_off + len(comment)
    str_off = rel_off + len(rela)
    shoff = str_off + len(strtab)
    shnum = len(names)
    buf = bytearray(shoff + 40 * shnum)
    buf[text_off : text_off + len(text)] = text
    buf[comment_off : comment_off + len(comment)] = comment
    buf[rel_off : rel_off + len(rela)] = rela
    buf[str_off : str_off + len(strtab)] = strtab

    def shdr(
        name: str, typ: int, flags: int, addr: int, off: int, size: int, entsize: int = 0
    ) -> bytes:
        return struct.pack(
            "<IIIIIIIIII", name_off[name], typ, flags, addr, off, size, 0, 0, 1, entsize
        )

    sections = [
        shdr("", 0, 0, 0, 0, 0),
        shdr(".text", 1, 6, entry, text_off, len(text)),
        shdr(".comment", 1, 0, 0, comment_off, len(comment)),
        shdr(".rel.dyn", 9, 0, 0, rel_off, len(rela), 8),
        shdr(".shstrtab", 3, 0, 0, str_off, len(strtab)),
    ]
    for index, raw in enumerate(sections):
        start = shoff + index * 40
        buf[start : start + 40] = raw
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        3,
        40,
        1,
        entry,
        52,
        shoff,
        0x05000000,
        52,
        32,
        1,
        40,
        shnum,
        shnum - 1,
    )
    phdr = struct.pack("<IIIIIIII", 1, 0, va, va, len(buf), len(buf), 5, 0x1000)
    buf[0:52] = ehdr
    buf[52:84] = phdr
    path.write_bytes(buf)


def test_arm32_entry_recovers_user_main(tmp_path: Path):
    pytest.importorskip("capstone")
    binary = tmp_path / "rust-arm"
    _arm_linux(binary)
    info = analyze_rust(binary)
    assert info is not None
    assert info["user_main"] == hex(0x8140)
    assert info["entry_chain"] == ["0x8100", "0x8120", "0x8140"]


def test_cortex_vector_reaches_user_main(tmp_path: Path):
    pytest.importorskip("capstone")
    binary = tmp_path / "fw"
    _elf32(binary)
    info = analyze_rust(binary)
    assert info is not None
    assert info["user_main"] == "0x120"
    assert info["entry_chain"] == ["0x100", "0x110", "0x120"]
    assert info["user_crates"] == ["fw_uart"]
    assert info["rustc_version"] == "1.80.0"
    assert info["rustc_commit"] == COMMIT
    assert info["functions"][0]["addr"] == "0x120"


def _brief(binary: Path, functions: list[dict] | None = None) -> dict:
    return build_briefing(
        {
            "binary": str(binary),
            "quick_scan": {},
            "deep_scan": {
                "radare2": {"functions": functions or [], "function_count": len(functions or [])}
            },
            "issues": [],
        }
    )


def test_briefing_rust_regions_sort_first_and_demangle(tmp_path: Path):
    pytest.importorskip("capstone")
    binary = tmp_path / "rust-aarch64"
    _aarch64_rust(binary)
    mangled = "_ZN3foo3bar17h0123456789abcdefE"
    payload = _brief(binary, [{"name": mangled, "offset": 0x2222, "size": 2000}])
    assert payload["rust"]["is_rust"] is True
    assert payload["rust"]["user_main"] == hex(USER)
    assert "why" not in payload["rust"]["functions"][0]
    top = payload["regions"][0]
    assert top["snippet"]["address"] == hex(USER)
    assert top["tags"][0] == "rust"
    assert payload["handoff"]["regions"][0]["addr"] == hex(USER)
    assert "decompile" not in " ".join(payload["handoff"]["next_argv"])
    assert f"user main {hex(USER)}" in payload["summary"]
    assert payload["handoff"]["summary"] == payload["summary"]
    titles = [region["title"] for region in payload["regions"]]
    assert any("foo::bar" in title for title in titles)
    assert all(mangled not in title for title in titles)
    assert payload["regions"][0]["score"] > payload["regions"][-1]["score"]


def test_missing_binary_does_not_add_rust_or_demangle(tmp_path: Path):
    mangled = "_ZN3foo3bar17h0123456789abcdefE"
    payload = _brief(tmp_path / "httpd", [{"name": mangled, "offset": 0x2222, "size": 2000}])
    assert "rust" not in payload
    assert any(mangled in region["title"] for region in payload["regions"])


def test_pac_prologue_reports_architectural_start(tmp_path: Path):
    """A `paciasp` function is reported at the prologue, never inside its body."""
    pytest.importorskip("capstone")
    binary = tmp_path / "rust-aarch64-pac"
    _aarch64_rust(binary)
    info = analyze_rust(binary)
    assert info is not None
    assert binary.read_bytes()[TEXT_OFF + (USER - ENTRY) :][:4] == PAC
    assert info["user_main"] == hex(USER)
    for item in info["functions"]:
        addr = int(item["addr"], 16)
        assert addr not in {USER + 0x40, REF + 0x40}



def _adr(rd: int, pc: int, target: int) -> bytes:
    imm = (target - pc) & ((1 << 21) - 1)
    immlo = imm & 3
    immhi = (imm >> 2) & 0x7FFFF
    return struct.pack("<I", (immlo << 29) | (0b10000 << 24) | (immhi << 5) | rd)


def _sub_sp(imm: int) -> bytes:
    return struct.pack("<I", 0xD1000000 | (imm << 10) | (31 << 5) | 31)


def _stp_fp_lr_pre() -> bytes:
    # stp x29, x30, [sp, #-16]!
    return struct.pack("<I", 0xA9BF7BFD)


def _aarch64_image(addr: int, data: bytes, extra: list[tuple[int, bytes]] | None = None) -> _Image:
    sections = [_Sec(".text", addr, data, 0x4)]
    loads = [(addr, data)]
    for other_addr, other in extra or ():
        sections.append(_Sec(f".text_{other_addr:x}", other_addr, other, 0x4))
        loads.append((other_addr, other))
    return _Image(arch="aarch64", bits=64, entry=addr, sections=sections, loads=loads)


def test_pac_prologue_is_one_function_boundary():
    """paciasp; sub sp; stp must snap refs and callees to the architectural start."""
    pytest.importorskip("capstone")
    start = 0x10000
    callee = 0x11000
    path_va = 0x20000
    body = (
        PAC
        + _sub_sp(0x20)
        + _stp_fp_lr_pre()
        + _adrp(1, start + 12, path_va & ~0xFFF)
        + _add(1, 1, path_va & 0xFFF)
        + _bl(start + 20, callee)
        + RET
    )
    image = _aarch64_image(start, body, extra=[(callee, RET + RET)])
    found = _callees(image, start)
    assert callee in found
    refs, starts = _sweep_xrefs(image, {path_va: ("user", "demo")})
    assert start in starts
    assert start + 4 not in starts
    assert start + 8 not in starts
    sites = [site for site, vas in refs.items() if path_va in vas]
    assert sites
    assert all(_snap(starts, site) == start for site in sites)
    assert _snap(starts, start + 12) == start


def test_callees_stop_at_return_before_neighbor():
    pytest.importorskip("capstone")
    start = 0x1000
    neighbor_bl = 0x1100
    data = RET + _sub_sp(0x10) + _bl(start + 8, neighbor_bl) + RET
    image = _aarch64_image(start, data, extra=[(neighbor_bl, RET)])
    assert neighbor_bl not in _callees(image, start)


def _write_low_va_adr_elf(path: Path) -> None:
    """PIE AArch64 ELF loaded at 0x1000. Entry and C main materialize targets with ADR."""
    entry = 0x1000
    lang = 0x1080
    c_main = 0x1100
    user = 0x2000
    text_off = 0x1000
    # File layout matches VA for a simple ET_DYN image.
    comment = _comment()
    comment_off = 0x2004
    names = ["", ".text", ".comment", ".shstrtab"]
    strtab = b"\x00".join(name.encode() for name in names) + b"\x00"
    name_off = {}
    cursor = 0
    for name in names:
        name_off[name] = cursor
        cursor += len(name) + 1
    str_off = comment_off + len(comment)
    shoff = str_off + len(strtab)
    shnum = len(names)
    buf = bytearray(shoff + 64 * shnum)
    buf[entry : entry + 12] = _adr(0, entry, c_main) + _bl(entry + 4, lang) + RET
    buf[lang : lang + 4] = RET
    buf[c_main : c_main + 12] = _adr(0, c_main, user) + _bl(c_main + 4, lang) + RET
    buf[user : user + 4] = RET
    buf[comment_off : comment_off + len(comment)] = comment
    buf[str_off : str_off + len(strtab)] = strtab

    def shdr(name: str, typ: int, flags: int, addr: int, off: int, size: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name_off[name], typ, flags, addr, off, size, 0, 0, 1, 0)

    sections = [
        shdr("", 0, 0, 0, 0, 0),
        shdr(".text", 1, 6, entry, text_off, 0x1004),
        shdr(".comment", 1, 0, 0, comment_off, len(comment)),
        shdr(".shstrtab", 3, 0, 0, str_off, len(strtab)),
    ]
    for index, raw in enumerate(sections):
        start = shoff + index * 64
        buf[start : start + 64] = raw
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        183,
        1,
        entry,
        64,
        shoff,
        0,
        64,
        56,
        1,
        64,
        shnum,
        shnum - 1,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0x1000,
        0x1000,
        0x1000,
        len(buf) - 0x1000,
        len(buf) - 0x1000,
        0x1000,
    )
    # e_phoff is 64, so the program header sits at 64 and must not overlap
    # the text at 0x1000. The ELF header occupies 0:64, phdr 64:120.
    buf[0:64] = ehdr
    buf[64:120] = phdr
    path.write_bytes(buf)


def test_aarch64_adr_uses_absolute_operand_at_low_va(tmp_path: Path):
    pytest.importorskip("capstone")
    path = tmp_path / "adr-pie"
    _write_low_va_adr_elf(path)
    info = analyze_rust(path)
    assert info is not None
    assert info["user_main"] == "0x2000"
    assert "0x2000" in info["entry_chain"]


def _elf32_at(path: Path, flash: int, sp: int) -> None:
    """Cortex-M image whose vector table is at ``flash``, not necessarily VA 0."""
    load_off = 0x100
    text_va = flash + 0x100
    tramp = flash + 0x110
    user = flash + 0x120
    ro_va = flash + 0x200
    text = bytearray(b"\x00" * 0x40)
    text[0:6] = _thumb_bl(text_va, tramp) + b"\x00\xde"
    text[0x10:0x18] = b"\x80\xb5\x6f\x46" + _thumb_bl(tramp + 4, user) + b"\x70\x47"
    text[0x20:0x22] = b"\x70\x47"
    path_s = b"fw_uart/src/main.rs"
    record = struct.pack("<IIII", ro_va + 16, len(path_s), 4, 2)
    ro = record + path_s + b"\x00" + f"/rustc/{COMMIT}/".encode()
    comment = b"rustc version 1.80.0 (aaaaaaaa 2024-01-01)\x00"
    names = ["", ".text", ".rodata", ".comment", ".isr_vector", ".shstrtab"]
    strtab = b"\x00".join(name.encode() for name in names) + b"\x00"
    name_off: dict[str, int] = {}
    cursor = 0
    for name in names:
        name_off[name] = cursor
        cursor += len(name) + 1
    ro_file = load_off + (ro_va - flash)
    comment_off = ro_file + len(ro)
    str_off = comment_off + len(comment)
    shoff = str_off + len(strtab)
    shnum = len(names)
    buf = bytearray(shoff + 40 * shnum)
    buf[load_off : load_off + 8] = struct.pack("<II", sp, text_va | 1)
    buf[load_off + (text_va - flash) : load_off + (text_va - flash) + len(text)] = text
    buf[ro_file : ro_file + len(ro)] = ro
    buf[comment_off : comment_off + len(comment)] = comment
    buf[str_off : str_off + len(strtab)] = strtab

    def shdr(name: str, typ: int, flags: int, addr: int, off: int, size: int) -> bytes:
        return struct.pack("<IIIIIIIIII", name_off[name], typ, flags, addr, off, size, 0, 0, 1, 0)

    sections = [
        shdr("", 0, 0, 0, 0, 0),
        shdr(".text", 1, 6, text_va, load_off + (text_va - flash), len(text)),
        shdr(".rodata", 1, 2, ro_va, ro_file, len(ro)),
        shdr(".comment", 1, 0, 0, comment_off, len(comment)),
        shdr(".isr_vector", 1, 2, flash, load_off, 8),
        shdr(".shstrtab", 3, 0, 0, str_off, len(strtab)),
    ]
    for index, raw in enumerate(sections):
        start = shoff + index * 40
        buf[start : start + 40] = raw
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        2,
        40,
        1,
        text_va | 1,
        52,
        shoff,
        0x05000000,
        52,
        32,
        1,
        40,
        shnum,
        shnum - 1,
    )
    filesz = len(buf) - load_off
    phdr = struct.pack("<IIIIIIII", 1, load_off, flash, flash, filesz, filesz, 5, 4)
    buf[0:52] = ehdr
    buf[52:84] = phdr
    path.write_bytes(buf)


def test_cortex_vector_at_flash_base(tmp_path: Path):
    pytest.importorskip("capstone")
    binary = tmp_path / "fw-flash"
    flash = 0x08000000
    _elf32_at(binary, flash, sp=0x10004000)
    info = analyze_rust(binary)
    assert info is not None
    assert info["user_main"] == hex(flash + 0x120)
    assert info["entry_chain"] == [hex(flash + 0x100), hex(flash + 0x110), hex(flash + 0x120)]
    assert info["user_crates"] == ["fw_uart"]


def test_non_rust_elf_with_rs_path_is_ignored(tmp_path: Path):
    binary = tmp_path / "c-with-rs"
    _elf64(binary, NOP * 8, b"foo/src/main.rs\x00", b"GCC: (GNU) 12\x00", b"")
    assert analyze_rust(binary) is None


def _thumb_ldr_pc(rt: int, pc: int, literal: int) -> bytes:
    # T1 ldr rt, [pc, #imm]. PC is (addr + 4) & ~3.
    base = (pc + 4) & ~3
    imm = literal - base
    assert imm >= 0 and imm % 4 == 0 and imm // 4 <= 0xFF
    return struct.pack("<H", 0x4800 | (rt << 8) | (imm // 4))


def _thumb_linux(path: Path) -> None:
    """Thumb-2 ARM Linux PIE. Entry LSB is set; path refs must be decoded as Thumb."""
    va = 0x8000
    text_off = 0x100
    entry = va + text_off
    c_main = entry + 0x20
    user = entry + 0x40
    path_va = va + 0x200
    text = bytearray(b"\x00" * 0x80)
    # _start: ldr r0, [pc, #4]; bl c_main; nop; .word c_main|1
    text[0:2] = _thumb_ldr_pc(0, entry, entry + 8)
    text[2:6] = _thumb_bl(entry + 2, c_main)
    text[6:8] = b"\x00\xbf"  # nop
    text[8:12] = struct.pack("<I", c_main | 1)
    # C main at +0x20: ldr r0, [pc, #4]; bl lang; nop; .word user|1
    text[0x20:0x22] = _thumb_ldr_pc(0, c_main, c_main + 8)
    text[0x22:0x26] = _thumb_bl(c_main + 2, c_main + 0x10)
    text[0x26:0x28] = b"\x00\xbf"
    text[0x28:0x2C] = struct.pack("<I", user | 1)
    text[0x30:0x32] = b"\x70\x47"  # bx lr at lang
    # user main: push {lr}; ldr r1, path; pop {pc}; .word path
    text[0x40:0x42] = b"\x00\xb5"  # push {lr}
    text[0x42:0x44] = _thumb_ldr_pc(1, user + 2, user + 8)
    text[0x44:0x46] = b"\x00\xbd"  # pop {pc}
    text[0x46:0x48] = b"\x00\xbf"
    text[0x48:0x4C] = struct.pack("<I", path_va)
    ro = b"demo_app/src/main.rs\x00" + f"/rustc/{COMMIT}/library/core/src/panic.rs".encode() + b"\x00"
    comment = _comment()
    names = ["", ".text", ".rodata", ".comment", ".shstrtab"]
    strtab = b"\x00".join(name.encode() for name in names) + b"\x00"
    name_off: dict[str, int] = {}
    cursor = 0
    for name in names:
        name_off[name] = cursor
        cursor += len(name) + 1
    ro_off = text_off + len(text)
    comment_off = ro_off + len(ro)
    str_off = comment_off + len(comment)
    shoff = str_off + len(strtab)
    shnum = len(names)
    buf = bytearray(shoff + 40 * shnum)
    buf[text_off : text_off + len(text)] = text
    buf[ro_off : ro_off + len(ro)] = ro
    buf[comment_off : comment_off + len(comment)] = comment
    buf[str_off : str_off + len(strtab)] = strtab

    def shdr(name: str, typ: int, flags: int, addr: int, off: int, size: int) -> bytes:
        return struct.pack("<IIIIIIIIII", name_off[name], typ, flags, addr, off, size, 0, 0, 1, 0)

    sections = [
        shdr("", 0, 0, 0, 0, 0),
        shdr(".text", 1, 6, entry, text_off, len(text)),
        shdr(".rodata", 1, 2, path_va, ro_off, len(ro)),
        shdr(".comment", 1, 0, 0, comment_off, len(comment)),
        shdr(".shstrtab", 3, 0, 0, str_off, len(strtab)),
    ]
    for index, raw in enumerate(sections):
        start = shoff + index * 40
        buf[start : start + 40] = raw
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        3,
        40,
        1,
        entry | 1,
        52,
        shoff,
        0x05000000,
        52,
        32,
        1,
        40,
        shnum,
        shnum - 1,
    )
    phdr = struct.pack("<IIIIIIII", 1, 0, va, va, len(buf), len(buf), 5, 0x1000)
    buf[0:52] = ehdr
    buf[52:84] = phdr
    path.write_bytes(buf)


def test_thumb_linux_path_refs_are_decoded_as_thumb(tmp_path: Path):
    pytest.importorskip("capstone")
    binary = tmp_path / "rust-thumb-linux"
    _thumb_linux(binary)
    info = analyze_rust(binary)
    assert info is not None
    assert info["user_main"] == hex(0x8140)
    addrs = [item["addr"] for item in info["functions"]]
    assert hex(0x8140) in addrs
    # The path load is in user main; a wrong A32 sweep would miss the user path
    # and could drop or mis-rank that function.
    user = next(item for item in info["functions"] if item["addr"] == hex(0x8140))
    assert user["role"] in {"user_main", "user"}


def test_ldr_w_reads_four_bytes_and_shifted_add():
    pytest.importorskip("capstone")
    # Place a 8-byte value at 0x2000 whose low 32 bits differ from the full 64.
    data_addr = 0x2000
    slot = (0x1122334455667788).to_bytes(8, "little")
    # ldr w0, [x1] at 0x1000; add x2, x2, #1, lsl #12 at 0x1004
    ldr_w = struct.pack("<I", 0xB9400020)  # ldr w0, [x1]
    add_shift = struct.pack("<I", 0x91400442)  # add x2, x2, #1, lsl #12
    text = ldr_w + add_shift
    image = _aarch64_image(0x1000, text, extra=[(data_addr, slot)])
    machine = None
    from r2b.analysis.rust import _Machine, _iter_insns

    machine = _Machine(image, False)
    machine.regs["x1"] = ("imm", data_addr)
    machine.regs["x2"] = ("imm", 1)
    insns = list(_iter_insns(image, 0x1000, False, 8))
    assert len(insns) == 2
    values, _refs, _call = machine.feed(insns[0])
    # 4-byte load must be 0x55667788, not the 8-byte 0x1122334455667788.
    assert machine.regs["x0"] == ("imm", 0x55667788)
    machine.feed(insns[1])
    assert machine.regs["x2"] == ("imm", 1 + (1 << 12))
