from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from r2b.adapters.binary_format import BinaryFormatAdapter, inspect_binary_format
from r2b.adapters.capstone import CapstoneAdapter, _resolve_mode
from r2b.analysis.briefing import build_briefing
from r2b.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2b.analysis.result_dto import analysis_result_core_dict


def _minimal_pe64() -> bytes:
    payload = bytearray(0x240)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    payload[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", payload, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", payload, optional, 0x20B)
    struct.pack_into("<I", payload, optional + 16, 0x1000)
    struct.pack_into("<Q", payload, optional + 24, 0x140000000)
    struct.pack_into("<I", payload, optional + 32, 0x1000)
    struct.pack_into("<I", payload, optional + 36, 0x200)
    struct.pack_into("<I", payload, optional + 56, 0x2000)
    struct.pack_into("<I", payload, optional + 60, 0x200)
    struct.pack_into("<H", payload, optional + 68, 3)
    struct.pack_into("<I", payload, optional + 108, 16)
    section = optional + 0xF0
    payload[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", payload, section + 8, 0x20, 0x1000, 0x20, 0x200)
    struct.pack_into("<I", payload, section + 36, 0x60000020)
    payload[0x200:0x204] = b"\x90\x90\xc3\x00"
    return bytes(payload)


def _minimal_macho64() -> bytes:
    payload = bytearray(0x140)
    struct.pack_into(
        "<IIIIIIII",
        payload,
        0,
        0xFEEDFACF,
        0x01000007,
        3,
        2,
        2,
        96,
        0x200000,
        0,
    )
    struct.pack_into(
        "<II16sQQQQiiII",
        payload,
        32,
        0x19,
        72,
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x100000000,
        0x1000,
        0,
        len(payload),
        7,
        5,
        0,
        0,
    )
    struct.pack_into("<IIQQ", payload, 104, 0x80000028, 24, 0x100, 0)
    payload[0x100:0x104] = b"\x90\x90\xc3\x00"
    return bytes(payload)


def test_pe_metadata_has_normalized_entrypoint(tmp_path: Path) -> None:
    binary = tmp_path / "shallow.exe"
    binary.write_bytes(_minimal_pe64())

    metadata = inspect_binary_format(binary)

    assert metadata["format"] == "pe"
    assert metadata["arch"] == "x86_64"
    assert metadata["bits"] == 64
    assert metadata["entrypoint"]["relative_virtual_address"] == 0x1000
    assert metadata["entrypoint"]["file_offset"] == 0x200
    assert metadata["sections"][0]["name"] == ".text"


def test_macho_metadata_has_normalized_entrypoint(tmp_path: Path) -> None:
    binary = tmp_path / "shallow"
    binary.write_bytes(_minimal_macho64())

    metadata = BinaryFormatAdapter().quick_scan(binary)

    assert metadata["format"] == "macho"
    assert metadata["arch"] == "x86_64"
    assert metadata["bits"] == 64
    assert metadata["entrypoint"]["file_offset"] == 0x100
    assert metadata["entrypoint"]["virtual_address"] == 0x100000100


class _FakeInstruction:
    address = 0x401000
    mnemonic = "ret"
    op_str = ""
    bytes = b"\xc3"


class _FakeDisassembler:
    def __init__(self, arch: int, mode: int) -> None:
        self.arch = arch
        self.mode = mode
        self.seen: tuple[bytes, int] | None = None

    def disasm(self, data: bytes, address: int):
        self.seen = (data, address)
        return [_FakeInstruction()]


class _FakeCapstone(SimpleNamespace):
    CS_ARCH_X86 = 1
    CS_ARCH_ARM = 2
    CS_ARCH_ARM64 = 3
    CS_MODE_16 = 16
    CS_MODE_32 = 32
    CS_MODE_64 = 64
    CS_MODE_ARM = 0
    CS_MODE_THUMB = 4
    CS_MODE_BIG_ENDIAN = 0x80000000
    CS_MODE_LITTLE_ENDIAN = 0

    def __init__(self) -> None:
        super().__init__()
        self.instance: _FakeDisassembler | None = None

    def Cs(self, arch: int, mode: int) -> _FakeDisassembler:
        self.instance = _FakeDisassembler(arch, mode)
        return self.instance


def test_capstone_reads_entrypoint_bytes_not_container_header(tmp_path: Path) -> None:
    binary = tmp_path / "subject.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 30 + b"\xc3" + b"\x90" * 63)
    fake = _FakeCapstone()
    metadata = {
        "format": "pe",
        "arch": "x86_64",
        "bits": 64,
        "endianness": "little",
        "entrypoint": {"virtual_address": 0x401000, "file_offset": 32},
    }

    with patch.object(CapstoneAdapter, "is_available", return_value=True), patch.object(
        CapstoneAdapter, "_capstone", return_value=fake
    ):
        result = CapstoneAdapter().quick_scan(binary, format_metadata=metadata)

    assert fake.instance is not None
    assert fake.instance.seen is not None
    assert fake.instance.seen[0].startswith(b"\xc3")
    assert not fake.instance.seen[0].startswith(b"MZ")
    assert fake.instance.seen[1] == 0x401000
    assert result["file_offset"] == 32


def test_capstone_modes_distinguish_x86_32_and_arm_thumb() -> None:
    fake = _FakeCapstone()

    assert _resolve_mode(fake, "x86", bits=32) == (fake.CS_ARCH_X86, fake.CS_MODE_32)
    assert _resolve_mode(fake, "arm", bits=32, instruction_set="thumb") == (
        fake.CS_ARCH_ARM,
        fake.CS_MODE_THUMB,
    )


def test_linux_arm32_thumb_hint_is_not_baremetal(tmp_path: Path) -> None:
    binary = tmp_path / "arm32-linux"
    analysis = {
        "binary": str(binary),
        "quick_scan": {
            "binary_format": {"format": "elf", "arch": "arm", "bits": 32},
            "firmware": {"is_elf": True, "is_executable": True, "top_level_format": "elf"},
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 16, "os": "linux"}, "core": {"format": "elf"}},
                "imports": [],
            },
        },
        "deep_scan": {},
        "issues": [],
    }

    briefing = build_briefing(analysis)

    assert briefing["subject"]["subject_class"] == "linux_elf"
    assert briefing["subject"]["arch"] == "arm/32"


def test_public_result_promotes_binary_format_metadata(tmp_path: Path) -> None:
    result = AnalysisResult(
        binary=tmp_path / "shallow.exe",
        plan=AnalysisPlan(),
        quick_scan={"binary_format": {"format": "pe", "arch": "x86_64", "bits": 64}},
    )

    payload = analysis_result_core_dict(result)

    assert payload["binary_format"] == {"format": "pe", "arch": "x86_64", "bits": 64}


def test_binary_format_classifies_code_without_firmware_payload(tmp_path: Path) -> None:
    binary = tmp_path / "shallow"
    analysis = {
        "binary": str(binary),
        "quick_scan": {
            "binary_format": {"format": "elf", "arch": "arm64", "bits": 64},
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 64, "os": "linux"}},
                "imports": [],
            },
        },
        "deep_scan": {},
        "issues": [],
    }

    briefing = build_briefing(analysis)

    assert briefing["subject"]["subject_class"] == "linux_elf"
