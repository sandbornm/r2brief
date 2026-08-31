"""Portable executable-format metadata for ELF, PE, and Mach-O subjects.

The adapter intentionally returns a small, normalized contract.  Native
parsers provide richer validation when installed, while bounded header
fallbacks keep intake useful when an optional parser rejects a damaged file.
Nothing here executes the subject.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": ("big", 32, False),
    b"\xce\xfa\xed\xfe": ("little", 32, False),
    b"\xfe\xed\xfa\xcf": ("big", 64, False),
    b"\xcf\xfa\xed\xfe": ("little", 64, False),
    b"\xca\xfe\xba\xbe": ("big", None, True),
    b"\xbe\xba\xfe\xca": ("little", None, True),
    b"\xca\xfe\xba\xbf": ("big", 64, True),
    b"\xbf\xba\xfe\xca": ("little", 64, True),
}

_PE_ARCHES = {
    0x014C: "x86",
    0x01C0: "arm",
    0x01C2: "arm",
    0x01C4: "arm",
    0x8664: "x86_64",
    0xAA64: "arm64",
    0x5032: "riscv32",
    0x5064: "riscv64",
}

_MACHO_ARCHES = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    18: "ppc",
    0x01000012: "ppc64",
}


@dataclass(slots=True)
class BinaryFormatAdapter:
    """Identify and normalize top-level executable metadata."""

    name: str = "binary_format"

    def is_available(self) -> bool:
        return True

    def quick_scan(self, binary: Path, **_: Any) -> dict[str, Any]:
        return inspect_binary_format(binary)

    def deep_scan(self, binary: Path, **_: Any) -> dict[str, Any]:
        return {"status": "skipped", "reason": "format metadata is a quick-stage capability"}


def inspect_binary_format(binary: Path) -> dict[str, Any]:
    """Return JSON-safe metadata without requiring an external executable."""

    target = Path(binary)
    try:
        with target.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        return {
            "format": "unknown",
            "parser": "builtin",
            "confidence": 0.0,
            "error": str(exc),
        }

    try:
        if magic == b"\x7fELF":
            return _inspect_elf(target)
        if magic[:2] == b"MZ":
            return _inspect_pe(target)
        if magic in _MACHO_MAGICS:
            return _inspect_macho(target, magic)
    except (OSError, ValueError, struct.error) as exc:
        return {
            "format": _format_from_magic(magic),
            "parser": "builtin",
            "confidence": 0.7,
            "error": str(exc),
        }
    return {
        "format": "unknown",
        "parser": "builtin",
        "confidence": 0.0,
        "magic": magic.hex(),
    }


def _inspect_elf(binary: Path) -> dict[str, Any]:
    try:
        from elftools.elf.elffile import ELFFile

        with binary.open("rb") as handle:
            elf = ELFFile(handle)
            entry = int(elf.header["e_entry"])
            instruction_set = "thumb" if elf.get_machine_arch() == "ARM" and entry & 1 else None
            normalized_entry = entry & ~1 if instruction_set == "thumb" else entry
            file_offset = _elf_file_offset(elf, normalized_entry)
            sections = []
            for section in list(elf.iter_sections())[:96]:
                sections.append(
                    {
                        "name": section.name,
                        "virtual_address": int(section["sh_addr"]),
                        "file_offset": int(section["sh_offset"]),
                        "size": int(section["sh_size"]),
                    }
                )
            return {
                "format": "elf",
                "parser": "pyelftools",
                "confidence": 1.0,
                "arch": _normalize_arch(elf.get_machine_arch()),
                "machine": str(elf.header["e_machine"]),
                "bits": int(elf.elfclass),
                "endianness": "little" if elf.little_endian else "big",
                "file_type": _normalize_file_type(str(elf.header["e_type"])),
                "entrypoint": {
                    "virtual_address": normalized_entry,
                    "file_offset": file_offset,
                    "instruction_set": instruction_set,
                },
                "sections": sections,
            }
    except (ImportError, ValueError, struct.error) as exc:
        metadata = _inspect_elf_header(binary)
        metadata["warning"] = f"pyelftools parse failed: {exc}"
        return metadata


def _elf_file_offset(elf: Any, virtual_address: int) -> int | None:
    for segment in elf.iter_segments():
        if str(segment["p_type"]) != "PT_LOAD":
            continue
        start = int(segment["p_vaddr"])
        file_size = int(segment["p_filesz"])
        if start <= virtual_address < start + file_size:
            return int(segment["p_offset"]) + virtual_address - start
    return None


def _inspect_elf_header(binary: Path) -> dict[str, Any]:
    with binary.open("rb") as handle:
        header = handle.read(64)
    if len(header) < 32:
        raise ValueError("truncated ELF header")
    bits = 64 if header[4] == 2 else 32 if header[4] == 1 else None
    endianness = "little" if header[5] == 1 else "big" if header[5] == 2 else "unknown"
    byte_order = "<" if endianness == "little" else ">"
    machine = struct.unpack_from(f"{byte_order}H", header, 18)[0]
    entry_format = "Q" if bits == 64 else "I"
    entry = struct.unpack_from(f"{byte_order}{entry_format}", header, 24)[0]
    arch = {3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "arm64", 243: "riscv"}.get(machine)
    instruction_set = "thumb" if arch == "arm" and entry & 1 else None
    if instruction_set:
        entry &= ~1
    return {
        "format": "elf",
        "parser": "builtin",
        "confidence": 0.9,
        "arch": arch,
        "machine": machine,
        "bits": bits,
        "endianness": endianness,
        "file_type": "executable",
        "entrypoint": {
            "virtual_address": entry,
            "file_offset": None,
            "instruction_set": instruction_set,
        },
        "sections": [],
    }


def _inspect_pe(binary: Path) -> dict[str, Any]:
    try:
        import pefile

        image = pefile.PE(str(binary), fast_load=True)
        try:
            machine = int(image.FILE_HEADER.Machine)
            optional = image.OPTIONAL_HEADER
            entry_rva = int(optional.AddressOfEntryPoint)
            image_base = int(optional.ImageBase)
            sections = [
                {
                    "name": section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                    "virtual_address": image_base + int(section.VirtualAddress),
                    "relative_virtual_address": int(section.VirtualAddress),
                    "file_offset": int(section.PointerToRawData),
                    "size": int(section.SizeOfRawData),
                }
                for section in image.sections[:96]
            ]
            try:
                entry_offset = int(image.get_offset_from_rva(entry_rva))
            except pefile.PEFormatError:
                entry_offset = None
            subsystem_id = int(optional.Subsystem)
            return {
                "format": "pe",
                "parser": "pefile",
                "confidence": 1.0,
                "arch": _PE_ARCHES.get(machine, f"pe-machine-{machine:#x}"),
                "machine": pefile.MACHINE_TYPE.get(machine, f"{machine:#x}"),
                "bits": 64 if int(optional.Magic) == 0x20B else 32,
                "endianness": "little",
                "file_type": "dll" if int(image.FILE_HEADER.Characteristics) & 0x2000 else "executable",
                "image_base": image_base,
                "subsystem": pefile.SUBSYSTEM_TYPE.get(subsystem_id, str(subsystem_id)),
                "entrypoint": {
                    "relative_virtual_address": entry_rva,
                    "virtual_address": image_base + entry_rva,
                    "file_offset": entry_offset,
                    "instruction_set": None,
                },
                "sections": sections,
            }
        finally:
            image.close()
    except (ImportError, AttributeError, OSError) as exc:
        metadata = _inspect_pe_header(binary)
        metadata["warning"] = f"pefile parse failed: {exc}"
        return metadata
    except Exception as exc:
        # pefile raises PEFormatError, whose import is intentionally optional.
        metadata = _inspect_pe_header(binary)
        metadata["warning"] = f"pefile parse failed: {exc}"
        return metadata


def _inspect_pe_header(binary: Path) -> dict[str, Any]:
    with binary.open("rb") as handle:
        dos = handle.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            raise ValueError("truncated DOS header")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        handle.seek(pe_offset)
        header = handle.read(24)
        if len(header) < 24 or header[:4] != b"PE\x00\x00":
            raise ValueError("invalid PE signature")
        machine, section_count, _, _, _, optional_size, characteristics = struct.unpack_from(
            "<HHIIIHH", header, 4
        )
        optional = handle.read(optional_size)
        if len(optional) < 32:
            raise ValueError("truncated PE optional header")
        magic = struct.unpack_from("<H", optional)[0]
        bits = 64 if magic == 0x20B else 32
        entry_rva = struct.unpack_from("<I", optional, 16)[0]
        image_base = struct.unpack_from("<Q" if bits == 64 else "<I", optional, 24 if bits == 64 else 28)[0]
        sections = _read_pe_sections(handle, section_count, image_base)
    entry_offset = _rva_to_file_offset(entry_rva, sections)
    return {
        "format": "pe",
        "parser": "builtin",
        "confidence": 0.9,
        "arch": _PE_ARCHES.get(machine, f"pe-machine-{machine:#x}"),
        "machine": machine,
        "bits": bits,
        "endianness": "little",
        "file_type": "dll" if characteristics & 0x2000 else "executable",
        "image_base": image_base,
        "entrypoint": {
            "relative_virtual_address": entry_rva,
            "virtual_address": image_base + entry_rva,
            "file_offset": entry_offset,
            "instruction_set": None,
        },
        "sections": sections,
    }


def _read_pe_sections(handle: BinaryIO, count: int, image_base: int) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for _ in range(min(count, 96)):
        raw = handle.read(40)
        if len(raw) < 40:
            break
        name = raw[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", raw, 8)
        sections.append(
            {
                "name": name,
                "virtual_address": image_base + rva,
                "relative_virtual_address": rva,
                "file_offset": raw_offset,
                "size": raw_size,
                "virtual_size": virtual_size,
            }
        )
    return sections


def _rva_to_file_offset(rva: int, sections: list[dict[str, Any]]) -> int | None:
    for section in sections:
        start = int(section["relative_virtual_address"])
        size = max(int(section["size"]), int(section.get("virtual_size") or 0))
        if start <= rva < start + size:
            return int(section["file_offset"]) + rva - start
    return None


def _inspect_macho(binary: Path, magic: bytes) -> dict[str, Any]:
    try:
        from macholib import MachO, mach_o

        image = MachO.MachO(str(binary))
        architectures: list[dict[str, Any]] = []
        for header in image.headers:
            cpu_type = int(header.header.cputype)
            slice_offset = int(getattr(header, "offset", 0) or 0)
            entry_file_offset: int | None = None
            entry_virtual_address: int | None = None
            segments: list[dict[str, Any]] = []
            entryoff: int | None = None
            for load_command, command, _data in header.commands:
                command_id = int(load_command.cmd)
                if command_id == int(mach_o.LC_MAIN):
                    entryoff = int(command.entryoff)
                if command_id in {int(mach_o.LC_SEGMENT), int(mach_o.LC_SEGMENT_64)}:
                    segment = {
                        "name": bytes(command.segname).rstrip(b"\x00").decode("ascii", errors="replace"),
                        "virtual_address": int(command.vmaddr),
                        "file_offset": slice_offset + int(command.fileoff),
                        "size": int(command.filesize),
                    }
                    segments.append(segment)
            if entryoff is not None:
                entry_file_offset = slice_offset + entryoff
                for segment in segments:
                    relative_offset = entry_file_offset - int(segment["file_offset"])
                    if 0 <= relative_offset < int(segment["size"]):
                        entry_virtual_address = int(segment["virtual_address"]) + relative_offset
                        break
            architectures.append(
                {
                    "arch": _MACHO_ARCHES.get(cpu_type, f"macho-cpu-{cpu_type:#x}"),
                    "cpu_type": cpu_type,
                    "bits": 64 if int(header.header.magic) in {mach_o.MH_MAGIC_64, mach_o.MH_CIGAM_64} else 32,
                    "file_type": mach_o.MH_FILETYPE_SHORTNAMES.get(int(header.header.filetype), "unknown"),
                    "slice_offset": slice_offset,
                    "entrypoint": {
                        "virtual_address": entry_virtual_address,
                        "file_offset": entry_file_offset,
                        "instruction_set": None,
                    },
                    "segments": segments,
                }
            )
        first = architectures[0] if architectures else {}
        return {
            "format": "fat_macho" if len(architectures) > 1 or _MACHO_MAGICS[magic][2] else "macho",
            "parser": "macholib",
            "confidence": 1.0,
            "arch": first.get("arch"),
            "bits": first.get("bits"),
            "endianness": _MACHO_MAGICS[magic][0],
            "file_type": first.get("file_type"),
            "entrypoint": first.get("entrypoint") or {},
            "sections": first.get("segments") or [],
            "architectures": architectures,
        }
    except (ImportError, AttributeError, IndexError, OSError, ValueError, struct.error) as exc:
        metadata = _inspect_macho_header(binary, magic)
        metadata["warning"] = f"macholib parse failed: {exc}"
        return metadata


def _inspect_macho_header(binary: Path, magic: bytes) -> dict[str, Any]:
    endianness, bits, is_fat = _MACHO_MAGICS[magic]
    byte_order = "<" if endianness == "little" else ">"
    with binary.open("rb") as handle:
        header = handle.read(32)
    if len(header) < 8:
        raise ValueError("truncated Mach-O header")
    if is_fat:
        arch_count = struct.unpack_from(f"{byte_order}I", header, 4)[0]
        return {
            "format": "fat_macho",
            "parser": "builtin",
            "confidence": 0.9,
            "arch": None,
            "bits": bits,
            "endianness": endianness,
            "file_type": "universal",
            "entrypoint": {},
            "sections": [],
            "architecture_count": arch_count,
        }
    if len(header) < 28:
        raise ValueError("truncated Mach-O header")
    cpu_type, _subtype, file_type = struct.unpack_from(f"{byte_order}III", header, 4)
    return {
        "format": "macho",
        "parser": "builtin",
        "confidence": 0.9,
        "arch": _MACHO_ARCHES.get(cpu_type, f"macho-cpu-{cpu_type:#x}"),
        "bits": bits,
        "endianness": endianness,
        "file_type": {1: "object", 2: "execute", 6: "dylib", 8: "bundle"}.get(file_type, "unknown"),
        "entrypoint": {},
        "sections": [],
    }


def _format_from_magic(magic: bytes) -> str:
    if magic == b"\x7fELF":
        return "elf"
    if magic[:2] == b"MZ":
        return "pe"
    if magic in _MACHO_MAGICS:
        return "fat_macho" if _MACHO_MAGICS[magic][2] else "macho"
    return "unknown"


def _normalize_arch(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower().replace("-", "_")
    return {
        "aarch64": "arm64",
        "arm": "arm",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "x86": "x86",
        "i386": "x86",
        "mips": "mips",
        "risc_v": "riscv",
    }.get(normalized, normalized or None)


def _normalize_file_type(value: str) -> str:
    normalized = value.lower()
    if "dyn" in normalized:
        return "shared_or_pie"
    if "exec" in normalized:
        return "executable"
    if "rel" in normalized:
        return "relocatable"
    if "core" in normalized:
        return "core"
    return normalized


__all__ = ["BinaryFormatAdapter", "inspect_binary_format"]
