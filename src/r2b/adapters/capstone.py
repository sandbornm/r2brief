"""Capstone disassembly adapter."""

from __future__ import annotations

import logging
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable
from .binary_format import inspect_binary_format

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class CapstoneAdapter:
    name: str = "capstone"

    def is_available(self) -> bool:
        try:
            import capstone  # type: ignore[import-untyped]  # noqa: F401
        except ModuleNotFoundError:
            return False
        return True

    def _capstone(self) -> types.ModuleType:
        try:
            import capstone
        except ModuleNotFoundError as exc:  # pragma: no cover - import guard
            raise AdapterUnavailable("capstone module is not installed") from exc
        return capstone  # type: ignore[no-any-return]

    def quick_scan(
        self,
        binary: Path,
        *,
        arch: str | None = None,
        bits: int | None = None,
        entry: int | None = None,
        file_offset: int | None = None,
        endianness: str | None = None,
        instruction_set: str | None = None,
        format_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.is_available():
            raise AdapterUnavailable("capstone is not available on this system")

        metadata = format_metadata or inspect_binary_format(binary)
        entrypoint = metadata.get("entrypoint") if isinstance(metadata.get("entrypoint"), dict) else {}
        arch = arch or _string_or_none(metadata.get("arch"))
        bits = bits or _int_or_none(metadata.get("bits"))
        entry = entry if entry is not None else _int_or_none(entrypoint.get("virtual_address"))
        file_offset = (
            file_offset
            if file_offset is not None
            else _int_or_none(entrypoint.get("file_offset"))
        )
        endianness = endianness or _string_or_none(metadata.get("endianness"))
        instruction_set = instruction_set or _string_or_none(entrypoint.get("instruction_set"))
        if arch is None:
            raise AdapterUnavailable("Architecture hint required for capstone quick scan")
        if file_offset is None:
            raise AdapterUnavailable("Entrypoint file offset is unavailable for capstone quick scan")

        capstone = self._capstone()
        mode = _resolve_mode(
            capstone,
            arch,
            bits=bits,
            endianness=endianness,
            instruction_set=instruction_set,
            entry=entry,
        )
        disassembler = capstone.Cs(*mode)
        try:
            with binary.open("rb") as handle:
                handle.seek(file_offset)
                data = handle.read(64)
        except OSError as exc:
            raise AdapterUnavailable(f"Unable to read entrypoint bytes: {exc}") from exc
        if not data:
            raise AdapterUnavailable(f"Entrypoint file offset {file_offset:#x} is outside the binary")
        disassembly_address = entry if entry is not None else file_offset
        if instruction_set == "thumb":
            disassembly_address &= ~1
        instructions = []
        for insn in disassembler.disasm(data, disassembly_address):
            instructions.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            })

        return {
            "instructions": instructions,
            "arch": arch,
            "bits": bits,
            "endianness": endianness,
            "instruction_set": instruction_set,
            "entrypoint": disassembly_address,
            "file_offset": file_offset,
            "bytes_read": len(data),
            "command": (
                f"capstone disasm (arch={arch}, bits={bits or 'auto'}, "
                f"entry={disassembly_address:#x}, file_offset={file_offset:#x})"
            ),
        }

    def deep_scan(self, binary: Path, *, blocks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if blocks is None:
            _LOGGER.debug("capstone deep scan skipped; no basic blocks provided")
            return {"status": "skipped", "reason": "no basic blocks"}
        return {"status": "pending", "blocks": len(blocks)}


def _resolve_mode(
    capstone: types.ModuleType,
    arch: str,
    *,
    bits: int | None = None,
    endianness: str | None = None,
    instruction_set: str | None = None,
    entry: int | None = None,
) -> tuple[int, int]:
    normalized = arch.strip().lower().replace("-", "_")
    if normalized in {"x86_64", "amd64", "x64"}:
        resolved = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif normalized in {"x86", "i386", "i486", "i586", "i686"}:
        x86_mode = capstone.CS_MODE_16 if bits == 16 else capstone.CS_MODE_32
        resolved = (capstone.CS_ARCH_X86, x86_mode)
    elif normalized in {"arm", "arm32"}:
        thumb = instruction_set == "thumb" or bool(entry is not None and entry & 1)
        resolved = (
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM,
        )
    elif normalized in {"arm64", "aarch64"}:
        resolved = (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    else:
        raise AdapterUnavailable(f"Unsupported architecture for capstone: {arch}")
    resolved_arch, resolved_mode = resolved
    if endianness == "big":
        resolved_mode |= capstone.CS_MODE_BIG_ENDIAN
    elif hasattr(capstone, "CS_MODE_LITTLE_ENDIAN"):
        resolved_mode |= capstone.CS_MODE_LITTLE_ENDIAN
    return resolved_arch, resolved_mode


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _string_or_none(value: Any) -> str | None:
    return str(value) if value not in {None, ""} else None
