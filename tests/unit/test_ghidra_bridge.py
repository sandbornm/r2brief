from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from r2b.adapters.ghidra_bridge_client import (
    CrossReference,
    DecompiledFunction,
    GhidraBridgeClient,
    GhidraTypeInfo,
)
from r2b.config import GhidraSettings
from r2b.environment.ghidra import GhidraDetection


class TestGhidraBridgeClient:

    def test_init_defaults(self):
        client = GhidraBridgeClient()

        assert client.host == "127.0.0.1"
        assert client.port == 13100
        assert client.timeout == 30
        assert client._bridge is None
        assert client._connected is False

    def test_init_custom_values(self):
        client = GhidraBridgeClient(
            host="192.168.1.100",
            port=13200,
            timeout=60,
        )

        assert client.host == "192.168.1.100"
        assert client.port == 13200
        assert client.timeout == 60

    def test_connect_returns_false_when_module_not_available(self):
        client = GhidraBridgeClient()

        with patch("builtins.__import__", side_effect=ImportError("ghidra_bridge")):
            result = client.connect()

        assert result is False
        assert client._connected is False

    def test_connect_returns_false_on_connection_error(self):
        client = GhidraBridgeClient()

        mock_bridge_module = MagicMock()
        mock_bridge_module.GhidraBridge.side_effect = ConnectionRefusedError()

        with patch.dict("sys.modules", {"ghidra_bridge": mock_bridge_module}):
            result = client.connect()

        assert result is False
        assert client._connected is False

    def test_connect_success(self):
        client = GhidraBridgeClient()

        mock_bridge = MagicMock()
        mock_bridge_module = MagicMock()
        mock_bridge_module.GhidraBridge.return_value = mock_bridge

        with patch.dict("sys.modules", {"ghidra_bridge": mock_bridge_module}):
            result = client.connect()

        assert result is True
        assert client._connected is True
        assert client._bridge is mock_bridge

    def test_is_connected_false_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.is_connected() is False

    def test_is_connected_false_when_ping_fails(self):
        client = GhidraBridgeClient()
        client._connected = True
        mock_bridge = MagicMock()
        mock_bridge.remote_import.side_effect = Exception("Connection lost")
        client._bridge = mock_bridge

        result = client.is_connected()

        assert result is False
        assert client._connected is False

    def test_disconnect(self):
        client = GhidraBridgeClient()
        client._connected = True
        client._bridge = MagicMock()

        client.disconnect()

        assert client._bridge is None
        assert client._connected is False

    def test_get_current_program_name_returns_none_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.get_current_program_name() is None

    def test_get_current_program_path_returns_none_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.get_current_program_path() is None

    def test_is_binary_loaded_returns_false_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.is_binary_loaded(Path("/test/binary")) is False

    def test_get_functions_returns_empty_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.get_functions() == []

    def test_decompile_function_returns_none_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.decompile_function(0x1000) is None

    def test_batch_decompile_returns_empty_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.batch_decompile([0x1000, 0x2000]) == []

    def test_get_types_returns_empty_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.get_types() == []

    def test_get_xrefs_to_returns_empty_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.get_xrefs_to(0x1000) == []

    def test_get_xrefs_from_returns_empty_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.get_xrefs_from(0x1000) == []

    def test_get_xrefs_for_functions_returns_empty_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.get_xrefs_for_functions([0x1000]) == {}

    def test_get_strings_returns_empty_when_not_connected(self):
        client = GhidraBridgeClient()
        assert client.get_strings() == []


class TestDecompiledFunction:

    def test_create_decompiled_function(self):
        func = DecompiledFunction(
            name="main",
            address=0x401000,
            signature="int main(int argc, char **argv)",
            decompiled_c="int main(int argc, char **argv) { return 0; }",
            parameters=[{"name": "argc", "type": "int"}],
            return_type="int",
            calling_convention="cdecl",
        )

        assert func.name == "main"
        assert func.address == 0x401000
        assert func.signature == "int main(int argc, char **argv)"
        assert "return 0" in func.decompiled_c
        assert len(func.parameters) == 1
        assert func.return_type == "int"
        assert func.calling_convention == "cdecl"

    def test_decompiled_function_is_frozen(self):
        func = DecompiledFunction(
            name="test",
            address=0x1000,
            signature="void test()",
            decompiled_c="",
            parameters=[],
            return_type="void",
        )

        with pytest.raises(AttributeError):
            func.name = "changed"


class TestGhidraTypeInfo:

    def test_create_struct_type(self):
        stype = GhidraTypeInfo(
            name="MyStruct",
            category="/user",
            size=16,
            kind="struct",
            members=[
                {"name": "field1", "type": "int", "offset": 0, "size": 4},
                {"name": "field2", "type": "long", "offset": 8, "size": 8},
            ],
        )

        assert stype.name == "MyStruct"
        assert stype.kind == "struct"
        assert stype.size == 16
        assert len(stype.members) == 2

    def test_create_enum_type(self):
        etype = GhidraTypeInfo(
            name="Color",
            category="/user",
            size=4,
            kind="enum",
            members=[
                {"name": "RED", "value": 0},
                {"name": "GREEN", "value": 1},
                {"name": "BLUE", "value": 2},
            ],
        )

        assert etype.name == "Color"
        assert etype.kind == "enum"
        assert len(etype.members) == 3


class TestCrossReference:

    def test_create_cross_reference(self):
        xref = CrossReference(
            from_address=0x401000,
            to_address=0x402000,
            ref_type="CALL",
            from_function="caller",
            to_function="callee",
        )

        assert xref.from_address == 0x401000
        assert xref.to_address == 0x402000
        assert xref.ref_type == "CALL"
        assert xref.from_function == "caller"
        assert xref.to_function == "callee"


class TestGhidraAdapter:

    def test_adapter_uses_headless_when_bridge_disabled(self):
        from r2b.adapters.ghidra import GhidraAdapter

        detection = GhidraDetection(
            install_dir=Path("/opt/ghidra"),
            headless_path=Path("/opt/ghidra/support/analyzeHeadless"),
            bridge_available=False,
            bridge_connected=False,
            extension_root=Path("/tmp/ext"),
        )
        settings = GhidraSettings(use_bridge=False)

        adapter = GhidraAdapter(
            detection=detection,
            project_dir=Path("/tmp/project"),
            settings=settings,
        )

        assert adapter._use_bridge_mode() is False

    def test_adapter_reports_available_when_headless_ready(self):
        from r2b.adapters.ghidra import GhidraAdapter

        detection = GhidraDetection(
            install_dir=Path("/opt/ghidra"),
            headless_path=Path("/opt/ghidra/support/analyzeHeadless"),
            bridge_available=False,
            bridge_connected=False,
            extension_root=Path("/tmp/ext"),
        )
        settings = GhidraSettings(use_bridge=False)

        adapter = GhidraAdapter(
            detection=detection,
            project_dir=Path("/tmp/project"),
            settings=settings,
        )

        assert adapter.is_available() is True

    def test_adapter_quick_scan_returns_mode(self):
        from r2b.adapters.ghidra import GhidraAdapter

        detection = GhidraDetection(
            install_dir=Path("/opt/ghidra"),
            headless_path=Path("/opt/ghidra/support/analyzeHeadless"),
            bridge_available=False,
            bridge_connected=False,
            extension_root=Path("/tmp/ext"),
        )
        settings = GhidraSettings(use_bridge=False)

        adapter = GhidraAdapter(
            detection=detection,
            project_dir=Path("/tmp/project"),
            settings=settings,
        )

        result = adapter.quick_scan(Path("/tmp/test.bin"))

        assert result["mode"] == "headless"
        assert result["status"] == "queued"

    def test_adapter_close_disconnects_bridge(self):
        from r2b.adapters.ghidra import GhidraAdapter

        detection = GhidraDetection(
            install_dir=Path("/opt/ghidra"),
            headless_path=Path("/opt/ghidra/support/analyzeHeadless"),
            bridge_available=True,
            bridge_connected=False,
            extension_root=Path("/tmp/ext"),
        )
        settings = GhidraSettings(use_bridge=True)

        adapter = GhidraAdapter(
            detection=detection,
            project_dir=Path("/tmp/project"),
            settings=settings,
        )

        mock_client = MagicMock()
        adapter._bridge_client = mock_client

        adapter.close()

        mock_client.disconnect.assert_called_once()
        assert adapter._bridge_client is None


class TestGhidraDetectionBridge:

    def test_bridge_ready_false_when_not_available(self):
        detection = GhidraDetection(
            install_dir=Path("/opt/ghidra"),
            headless_path=Path("/opt/ghidra/support/analyzeHeadless"),
            bridge_available=False,
            bridge_connected=False,
            extension_root=Path("/tmp/ext"),
        )

        assert detection.bridge_ready is False

    def test_bridge_ready_false_when_not_connected(self):
        detection = GhidraDetection(
            install_dir=Path("/opt/ghidra"),
            headless_path=Path("/opt/ghidra/support/analyzeHeadless"),
            bridge_available=True,
            extension_root=Path("/tmp/ext"),
            bridge_connected=False,
        )

        assert detection.bridge_ready is False

    def test_bridge_ready_true_when_connected(self):
        detection = GhidraDetection(
            install_dir=Path("/opt/ghidra"),
            headless_path=Path("/opt/ghidra/support/analyzeHeadless"),
            bridge_available=True,
            extension_root=Path("/tmp/ext"),
            bridge_connected=True,
            bridge_program_loaded="test.bin",
        )

        assert detection.bridge_ready is True
        assert detection.bridge_program_loaded == "test.bin"


class TestGhidraBridgeScriptExecution:

    def test_execute_script_not_connected(self):
        client = GhidraBridgeClient()
        result = client.execute_script("print('test')")

        assert result["error"] is not None
        assert "not connected" in result["error"].lower()

    def test_execute_script_success(self):
        client = GhidraBridgeClient()
        client._connected = True

        mock_bridge = MagicMock()
        client._bridge = mock_bridge

        with patch.object(
            client,
            "_execute_remote",
            return_value={"output": "Found 3 functions", "error": None},
        ):
            result = client.execute_script("print(len(functions))")

        assert result["error"] is None
        assert "Found 3 functions" in result["output"]

    def test_execute_script_timeout(self):
        client = GhidraBridgeClient(timeout=1)
        client._connected = True

        mock_bridge = MagicMock()
        client._bridge = mock_bridge

        with patch.object(
            client, "_execute_remote", side_effect=TimeoutError("Script execution timed out")
        ):
            result = client.execute_script("while True: pass", timeout=1)

        assert result["error"] is not None
        assert "timeout" in result["error"].lower()

    def test_execute_script_handles_generic_exception(self):
        client = GhidraBridgeClient()
        client._connected = True

        mock_bridge = MagicMock()
        client._bridge = mock_bridge

        with patch.object(
            client, "_execute_remote", side_effect=RuntimeError("Remote execution failed")
        ):
            result = client.execute_script("bad_code()")

        assert result["error"] is not None
        assert "Remote execution failed" in result["error"]

    def test_execute_remote_wraps_script_for_stdout_capture(self):
        client = GhidraBridgeClient()
        client._connected = True

        mock_bridge = MagicMock()

        captured_namespace = {}

        def mock_remote_exec(script, namespace):
            captured_namespace.update(namespace)
            namespace["_r2b_result"] = "Hello from Ghidra"

        mock_bridge.remote_exec = mock_remote_exec
        client._bridge = mock_bridge

        result = client._execute_remote("print('Hello from Ghidra')")

        assert result["error"] is None
        assert result["output"] == "Hello from Ghidra"

    def test_execute_remote_returns_error_when_bridge_none(self):
        client = GhidraBridgeClient()
        client._connected = True
        client._bridge = None

        result = client._execute_remote("print('test')")

        assert result["error"] is not None
        assert "not initialized" in result["error"].lower()

    def test_execute_remote_handles_remote_exec_exception(self):
        client = GhidraBridgeClient()
        client._connected = True

        mock_bridge = MagicMock()
        mock_bridge.remote_exec.side_effect = Exception("RPC error")
        client._bridge = mock_bridge

        result = client._execute_remote("print('test')")

        assert result["error"] is not None
        assert "RPC error" in result["error"]

    def test_indent_script_helper(self):
        script = "line1\nline2\nline3"
        result = GhidraBridgeClient._indent_script(script)

        assert result == "    line1\n    line2\n    line3"

    def test_indent_script_custom_indent(self):
        script = "a\nb"
        result = GhidraBridgeClient._indent_script(script, indent="  ")

        assert result == "  a\n  b"
