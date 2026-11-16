"""Static Rust triage over synthetic ELF bytes. No eval corpus."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from r2b.analysis.briefing import build_briefing
from r2b.analysis.rust import _cortex_reset, analyze_rust, classify_path

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
