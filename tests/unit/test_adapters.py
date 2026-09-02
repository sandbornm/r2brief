"""Unit tests for analysis adapters."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from r2b.adapters.base import AdapterRegistry, AdapterUnavailable


class TestAdapterRegistry:
    """Tests for AdapterRegistry."""

    def test_available_returns_only_available_adapters(self, mock_adapter, unavailable_adapter):
        """Test that available() filters out unavailable adapters."""
        registry = AdapterRegistry([mock_adapter, unavailable_adapter])
        available = registry.available()

        assert len(available) == 1
        assert available[0].name == "mock"

    def test_get_returns_available_adapter(self, mock_adapter):
        """Test get() returns adapter when available."""
        registry = AdapterRegistry([mock_adapter])
        adapter = registry.get("mock")

        assert adapter is mock_adapter

    def test_get_raises_for_unavailable_adapter(self, unavailable_adapter):
        """Test get() raises AdapterUnavailable for unavailable adapter."""
        registry = AdapterRegistry([unavailable_adapter])

        with pytest.raises(AdapterUnavailable) as exc_info:
            registry.get("unavailable")

        assert "not available" in str(exc_info.value)

    def test_get_raises_for_unregistered_adapter(self, mock_adapter):
        """Test get() raises AdapterUnavailable for unregistered adapter."""
        registry = AdapterRegistry([mock_adapter])

        with pytest.raises(AdapterUnavailable) as exc_info:
            registry.get("nonexistent")

        assert "not registered" in str(exc_info.value)

    def test_empty_registry_returns_empty_available(self):
        """Test empty registry returns empty list from available()."""
        registry = AdapterRegistry([])
        assert registry.available() == []


class TestMockAdapter:
    """Tests for mock adapter behavior (validates test fixtures)."""

    def test_mock_adapter_is_available(self, mock_adapter):
        """Test mock adapter reports as available."""
        assert mock_adapter.is_available() is True

    def test_mock_adapter_quick_scan(self, mock_adapter, sample_elf_file):
        """Test mock adapter quick_scan returns expected structure."""
        result = mock_adapter.quick_scan(sample_elf_file)

        assert result["mock"] is True
        assert str(sample_elf_file) in result["binary"]
        assert mock_adapter.quick_scan_called is True

    def test_mock_adapter_deep_scan(self, mock_adapter, sample_elf_file):
        """Test mock adapter deep_scan returns expected structure."""
        result = mock_adapter.deep_scan(sample_elf_file)

        assert result["mock"] is True
        assert "functions" in result
        assert "cfg" in result
        assert mock_adapter.deep_scan_called is True

    def test_unavailable_adapter_is_not_available(self, unavailable_adapter):
        """Test unavailable adapter reports as not available."""
        assert unavailable_adapter.is_available() is False


class TestRadare2Adapter:
    """Tests for Radare2Adapter (mocked)."""

    def test_is_available_checks_binary_and_module(self):
        """Test is_available checks both radare2 binary and r2pipe module."""
        from r2b.adapters.radare2 import Radare2Adapter

        adapter = Radare2Adapter()

        # Test with mocked shutil.which and module check
        with patch("shutil.which") as mock_which:
            mock_which.return_value = None
            assert adapter.is_available() is False

    def test_module_available_returns_false_when_missing(self):
        """Test _module_available returns False when r2pipe not installed."""
        from r2b.adapters.radare2 import Radare2Adapter

        adapter = Radare2Adapter()

        with patch.dict("sys.modules", {"r2pipe": None}):
            # Force reimport check
            with patch("builtins.__import__", side_effect=ModuleNotFoundError):
                assert adapter._module_available() is False

    def test_verify_scan_follows_aarch64_got_data_reference(self):
        """A reloc DATA xref can lead to a nearby indirect ``blr`` call."""
        from r2b.adapters.radare2 import Radare2Adapter

        class FakeSession:
            def __init__(self):
                self.commands: list[str] = []
                self.closed = False

            def cmd(self, command: str) -> str:
                self.commands.append(command)
                responses = {
                    "ij": '{"bin":{"arch":"arm","bits":64}}',
                    "axt @ sym.imp.execl": "",
                    "axt @ reloc.execl": (
                        "fcn.000092e4 0x936c [DATA:r--] ldr x4, reloc.execl"
                    ),
                    "pd -16 @ 0x936c": "",
                    "pd 8 @ 0x936c": "\n".join(
                        [
                            "0x0000936c 84b045f9 ldr x4, [x4, 0xb60] ; reloc.execl",
                            "0x00009374 e20301aa mov x2, x1",
                            "0x00009380 e00301aa mov x0, x1",
                            "0x00009384 80003fd6 blr x4",
                        ]
                    ),
                    "afo @ 0x00009384": "0x000092e4",
                }
                return responses.get(command, "")

            def quit(self) -> None:
                self.closed = True

        adapter = Radare2Adapter()
        session = FakeSession()

        with (
            patch.object(Radare2Adapter, "is_available", return_value=True),
            patch.object(Radare2Adapter, "_open", return_value=session),
        ):
            result = adapter.verify_scan(Path("/tmp/uhttpd"), ["execl"])

        assert result == [
            {
                "import": "execl",
                "status": "dynamic",
                "call_sites": [
                    {
                        "function": "000092e4",
                        "function_addr": "0x000092e4",
                        "address": "0x00009384",
                        "argument": "<dynamic>",
                        "constant": False,
                    }
                ],
            }
        ]
        assert "axt @ reloc.execl" in session.commands
        assert "afo @ 0x00009384" in session.commands
        assert session.closed is True

    def test_verify_scan_uses_afo_for_containing_function_va(self):
        """Call-site VAs get a decompile-ready function start from r2 ``afo``."""
        from r2b.adapters.radare2 import Radare2Adapter

        class FakeSession:
            def __init__(self):
                self.commands: list[str] = []
                self.closed = False

            def cmd(self, command: str) -> str:
                self.commands.append(command)
                responses = {
                    "ij": '{"bin":{"arch":"arm","bits":64}}',
                    "axt @ sym.imp.strcpy": "",
                    "axt @ reloc.strcpy": (
                        "fcn.00004a3c 0x4ba8 [CALL:--x] blr x2"
                    ),
                    "pd -16 @ 0x4ba8": (
                        "0x00004b80 42d846f9 ldr x2, [x2, 0xdb0] ; reloc.strcpy"
                    ),
                    "pd 8 @ 0x4ba8": "0x00004ba8 40003fd6 blr x2",
                    "afo @ 0x00004ba8": "0x00004a3c",
                }
                return responses.get(command, "")

            def quit(self) -> None:
                self.closed = True

        adapter = Radare2Adapter()
        session = FakeSession()

        with (
            patch.object(Radare2Adapter, "is_available", return_value=True),
            patch.object(Radare2Adapter, "_open", return_value=session),
        ):
            result = adapter.verify_scan(Path("/tmp/ubusd"), ["strcpy"])

        site = result[0]["call_sites"][0]
        assert site["address"] == "0x00004ba8"
        assert site["function_addr"] == "0x00004a3c"
        assert "afo @ 0x00004ba8" in session.commands
        assert session.closed is True

    def test_quick_entry_uses_function_listing_not_raw_bytes(self):
        """Unanalyzed `pD N` can tear an instruction; `pdf` after `af` must win."""
        from r2b.adapters.radare2 import Radare2Adapter

        torn = (
            "            ;-- main:\n"
            "            0x08048880      55             push ebp\n"
            "            0x0804889e      c7             invalid\n"
        )
        pdf = (
            "┌ 382: int main (char **argv, char **envp);\n"
            "│           0x08048880      55             push ebp\n"
            "│           0x0804889e      c745f40000..   mov dword [var_ch], 0\n"
            "│           0x08048930      e8cb000000     call dbg.cgc_check\n"
        )

        class FakeSession:
            def __init__(self) -> None:
                self.commands: list[str] = []

            def cmd(self, command: str) -> str:
                self.commands.append(command)
                if command.startswith("pD"):
                    return torn
                if command.startswith("pdf"):
                    return pdf
                if command.startswith("pdj"):
                    return "[]"
                if command.startswith("pd "):
                    return pdf
                return ""

        session = FakeSession()
        entry, listing = Radare2Adapter._quick_entry(
            session,
            [{"name": "main", "vaddr": 0x08048880, "type": "FUNC"}],
            [],
        )
        assert entry is not None
        assert entry["name"] == "main"
        assert listing is not None
        last = [line for line in listing.splitlines() if line.strip()][-1]
        assert "invalid" not in last.lower()
        assert "cgc_check" in listing
        assert any(cmd.startswith("pdf") or cmd.startswith("pd ") for cmd in session.commands)
        assert not any(cmd.startswith("aaa") or cmd.startswith("aaaa") for cmd in session.commands)

    def test_quick_entry_falls_back_to_pd_when_pdf_empty(self):
        from r2b.adapters.radare2 import Radare2Adapter

        class FakeSession:
            def __init__(self) -> None:
                self.commands: list[str] = []

            def cmd(self, command: str) -> str:
                self.commands.append(command)
                if command.startswith("pD"):
                    return "0x0804889e      c7             invalid\n"
                if command.startswith("pdf"):
                    return ""
                if command.startswith("pd "):
                    return "0x08048880  push ebp\n0x08048881  mov ebp, esp\n"
                return ""

        _entry, listing = Radare2Adapter._quick_entry(
            FakeSession(),
            [{"name": "main", "vaddr": 0x08048880}],
            [],
        )
        assert listing is not None
        assert "push ebp" in listing
        assert "invalid" not in listing.lower()

    def test_builtin_pdc_is_not_r2ghidra(self):
        from r2b.adapters.radare2 import parse_decompiler_backends

        caps = parse_decompiler_backends("pdc\n")
        assert caps.r2ghidra is False
        assert caps.r2dec is False
        assert caps.pdc is True
        assert "pdc" in caps.backends

    def test_pdg_in_ld_is_r2ghidra(self):
        from r2b.adapters.radare2 import parse_decompiler_backends

        caps = parse_decompiler_backends("pdc\npdg\n")
        assert caps.r2ghidra is True
        assert "pdg" in caps.backends

    def test_pdd_in_ld_is_r2dec(self):
        from r2b.adapters.radare2 import parse_decompiler_backends

        caps = parse_decompiler_backends("pdc\npdd\n")
        assert caps.r2dec is True
        assert caps.r2ghidra is False
        assert "pdd" in caps.backends

    def test_try_decompile_prefers_pdg_when_listed(self):
        from r2b.adapters.radare2 import Radare2Adapter, parse_decompiler_backends

        class FakeSession:
            def __init__(self) -> None:
                self.commands: list[str] = []

            def cmd(self, command: str) -> str:
                self.commands.append(command)
                if command == "pdg":
                    return "ulong main(void) { return 0; }\n"
                if command == "pdd":
                    return "int main() { return 0; }\n"
                return ""

        caps = parse_decompiler_backends("pdc\npdg\npdd\n")
        result = Radare2Adapter._try_decompile(FakeSession(), 0x1000, caps)
        assert result is not None
        assert result["command"] == "pdg"
        assert "main" in result["text"]

    def test_try_decompile_skips_when_no_plugin(self):
        from r2b.adapters.radare2 import Radare2Adapter, parse_decompiler_backends

        class FakeSession:
            def cmd(self, command: str) -> str:
                raise AssertionError(f"unexpected command {command}")

        caps = parse_decompiler_backends("pdc\n")
        assert Radare2Adapter._try_decompile(FakeSession(), 0x1000, caps) is None

    def test_env_probe_does_not_claim_r2ghidra_from_builtin_pdc(self):
        from r2b.environment.detectors import _r2_decompiler_checks

        with (
            patch("r2b.environment.detectors.shutil.which", return_value="/usr/bin/r2"),
            patch(
                "r2b.environment.detectors.subprocess.check_output",
                return_value=b"pdc\nR2B_CORE\n",
            ),
        ):
            checks = _r2_decompiler_checks()
        by_name = {item.name: item for item in checks}
        assert by_name["r2ghidra"].available is False
        assert by_name["r2dec"].available is False


_PALINDROME = Path("/home/kali/work/github/r2brief/.r2b-corpus/work/darpa-cgc-eval/bin/Palindrome")
_HELLO = Path(__file__).resolve().parents[2] / "samples" / "bin" / "arm64" / "hello"


def _radare2_available() -> bool:
    from r2b.adapters.radare2 import Radare2Adapter

    return Radare2Adapter().is_available()


class TestRadare2QuickListingLive:
    """Live r2 listing quality. Skips when r2 or the corpus binary is missing."""

    @pytest.mark.skipif(
        not _PALINDROME.is_file() or not _radare2_available(),
        reason="radare2 or Palindrome corpus binary missing",
    )
    def test_palindrome_quick_listing_is_not_torn_invalid(self):
        from r2b.adapters.radare2 import Radare2Adapter

        result = Radare2Adapter().quick_scan(_PALINDROME)
        listing = str(result.get("entry_disassembly") or "")
        assert listing.strip()
        code_lines = [line for line in listing.splitlines() if "0x" in line]
        assert code_lines
        assert "invalid" not in code_lines[-1].lower()
        joined = "\n".join(code_lines).lower()
        assert "invalid" not in joined
        assert "call" in joined
        assert "cgc_check" in listing
        commands = " ".join(str(cmd) for cmd in result.get("commands") or [])
        assert "aaaa" not in commands.split()

    @pytest.mark.skipif(not _HELLO.is_file() or not _radare2_available(), reason="radare2 or hello sample missing")
    def test_quick_scan_reports_decompiler_caps_from_ld(self):
        from r2b.adapters.radare2 import Radare2Adapter

        result = Radare2Adapter().quick_scan(_HELLO)
        caps = result.get("capabilities") or {}
        backends = list(caps.get("decompilers") or [])
        assert caps.get("r2ghidra") is bool("pdg" in backends or "r2ghidra" in backends)
        if "pdd" in backends:
            assert caps.get("r2dec") is True


class TestCapstoneAdapter:
    """Tests for CapstoneAdapter."""

    def test_is_available_checks_module(self):
        """Test is_available checks capstone module availability."""
        from r2b.adapters.capstone import CapstoneAdapter

        adapter = CapstoneAdapter()
        # This should work if capstone is installed
        result = adapter.is_available()
        assert isinstance(result, bool)


class TestAngrAdapter:
    """Tests for AngrAdapter (mocked)."""

    def test_is_available_checks_module(self):
        """Test is_available checks angr module availability."""
        from r2b.adapters.angr import AngrAdapter

        # Mock at module import level to avoid broken angr dependency issues
        with patch.dict("sys.modules", {"angr": MagicMock()}):
            adapter = AngrAdapter()
            # When angr import succeeds, is_available should return True
            result = adapter.is_available()
            assert result is True

        # Test when angr is not installed
        with patch("builtins.__import__", side_effect=ModuleNotFoundError("angr")):
            adapter = AngrAdapter()
            result = adapter.is_available()
            assert result is False

    def test_quick_scan_raises_when_unavailable(self):
        """Test quick_scan raises AdapterUnavailable when angr not installed."""
        from r2b.adapters.angr import AngrAdapter

        adapter = AngrAdapter()

        # Patch the is_available method at class level
        with patch.object(AngrAdapter, "is_available", return_value=False):
            with pytest.raises(AdapterUnavailable):
                adapter.quick_scan(Path("/tmp/test.bin"))

    def test_deep_scan_raises_when_unavailable(self):
        """Test deep_scan raises AdapterUnavailable when angr not installed."""
        from r2b.adapters.angr import AngrAdapter

        adapter = AngrAdapter()

        # Patch the is_available method at class level
        with patch.object(AngrAdapter, "is_available", return_value=False):
            with pytest.raises(AdapterUnavailable):
                adapter.deep_scan(Path("/tmp/test.bin"))

    def test_cfg_uses_executable_segments_when_sections_are_absent(self):
        from r2b.adapters.angr import _cfg_options_for_project

        main_object = MagicMock()
        main_object.sections = []
        main_object.segments = [
            MagicMock(is_executable=True, min_addr=0x401000, max_addr=0x402FFF),
            MagicMock(is_executable=False, min_addr=0x403000, max_addr=0x404FFF),
        ]
        project = MagicMock()
        project.loader.main_object = main_object

        options = _cfg_options_for_project(project)

        assert options["regions"] == [(0x401000, 0x403000)]
        assert options["force_smart_scan"] is False
        assert options["force_complete_scan"] is True

    def test_cfg_keeps_default_scan_when_executable_section_exists(self):
        from r2b.adapters.angr import _cfg_options_for_project

        main_object = MagicMock()
        main_object.sections = [MagicMock(is_executable=True, memsize=4096)]
        main_object.segments = [MagicMock(is_executable=True, min_addr=0x1000, max_addr=0x1FFF)]
        project = MagicMock()
        project.loader.main_object = main_object

        options = _cfg_options_for_project(project)

        assert options == {
            "normalize": True,
            "data_references": True,
            "force_complete_scan": False,
        }


class TestLibmagicAdapter:
    """Tests for LibmagicAdapter."""

    def test_is_available_checks_module(self):
        """Test is_available checks python-magic module."""
        from r2b.adapters.libmagic import LibmagicAdapter

        adapter = LibmagicAdapter()
        result = adapter.is_available()
        assert isinstance(result, bool)
