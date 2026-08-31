"""Analysis adapter implementations."""

from .angr import AngrAdapter
from .autoprofile import AutoProfileAdapter
from .binary_format import BinaryFormatAdapter
from .capstone import CapstoneAdapter
from .dwarf import DWARFAdapter
from .frida import FridaAdapter
from .firmware import FirmwareAdapter
from .gef import GEFAdapter
from .ghidra import GhidraAdapter
from .ghidra_bridge_client import (
    CrossReference,
    DecompiledFunction,
    GhidraBridgeClient,
    GhidraTypeInfo,
)
from .libmagic import LibmagicAdapter
from .radare2 import Radare2Adapter

__all__ = [
    "AngrAdapter",
    "AutoProfileAdapter",
    "BinaryFormatAdapter",
    "CapstoneAdapter",
    "CrossReference",
    "DecompiledFunction",
    "DWARFAdapter",
    "FirmwareAdapter",
    "FridaAdapter",
    "GEFAdapter",
    "GhidraAdapter",
    "GhidraBridgeClient",
    "GhidraTypeInfo",
    "LibmagicAdapter",
    "Radare2Adapter",
]
