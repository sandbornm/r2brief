from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..config import GhidraSettings
from ..environment.ghidra import GhidraDetection
from .base import AdapterUnavailable

if TYPE_CHECKING:
    from .ghidra_bridge_client import GhidraBridgeClient

_LOGGER = logging.getLogger(__name__)
_DECOMPILE_HEADER_RE = re.compile(
    r"^// ==== \S+ @ (?:0x)?([0-9a-f]+) ====",
    re.IGNORECASE,
)


def resolve_decompile_function_va(binary: Path, address: str) -> str | None:
    from ..analysis.verify import parse_function_va

    given = parse_function_va(address)
    try:
        from .radare2 import Radare2Adapter

        adapter = Radare2Adapter()
        if adapter.is_available() and binary.is_file():
            found = adapter.containing_function_va(binary, address)
            if found:
                return found
    except Exception as exc:
        _LOGGER.debug("containing-function lookup failed for %s: %s", address, exc)
    return given


def _function_addr_from_decompile_c(text: str) -> str | None:
    from ..analysis.verify import parse_function_va

    for line in text.splitlines():
        match = _DECOMPILE_HEADER_RE.match(line.strip())
        if match:
            return parse_function_va(match.group(1))
    return None


@dataclass
class GhidraAdapter:

    detection: GhidraDetection
    project_dir: Path
    settings: GhidraSettings | None = None
    default_project: str = "r2b"
    name: str = "ghidra"

    _bridge_client: "GhidraBridgeClient | None" = field(default=None, repr=False)

    def is_available(self) -> bool:
        return self.detection.headless_ready or self.detection.bridge_ready

    def _use_bridge_mode(self) -> bool:
        return self.detection.bridge_ready

    def _get_mode(self) -> str:
        if self._use_bridge_mode():
            return "bridge"
        if self.detection.headless_ready:
            return "headless"
        return "unavailable"

    def quick_scan(self, binary: Path) -> dict[str, Any]:
        return {
            "status": "queued",
            "message": "Ghidra runs in deep analysis stage only",
            "binary": str(binary),
            "mode": self._get_mode(),
        }

    def deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
        script: Path | None = None,
        project_name: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        
        if self._use_bridge_mode():
            try:
                return self._bridge_deep_scan(binary, resource_tree=resource_tree)
            except Exception as exc:
                _LOGGER.warning("Bridge scan failed, falling back to headless: %s", exc)

        if self.detection.headless_ready:
            return self._headless_deep_scan(
                binary,
                resource_tree=resource_tree,
                script=script,
                project_name=project_name,
                dry_run=dry_run,
            )

        raise AdapterUnavailable("Ghidra not available. Set GHIDRA_INSTALL_DIR.")

    def decompile_function(self, binary: Path, address: str) -> dict[str, Any]:
        if not self.detection.headless_ready:
            raise AdapterUnavailable("Ghidra headless not available")

        script = self._script_path("DecompileTargets.java")

        requested_hex = address.lower().removeprefix("0x")
        function_addr = resolve_decompile_function_va(binary, address)
        target_hex = function_addr.lower().removeprefix("0x") if function_addr else requested_hex
        project_dir = Path(self.project_dir).expanduser()
        project_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as tmp:
            output_path = tmp.name

        command = [
            str(self.detection.headless_path),
            str(project_dir),
            f"r2b-fn-{binary.name}",
            "-import",
            str(binary),
            "-overwrite",
            "-scriptPath",
            str(script.parent),
            "-postScript",
            script.name,
            output_path,
            target_hex,
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=180,
            )
            text = Path(output_path).read_text(encoding="utf-8") if Path(output_path).is_file() else ""
            header_va = _function_addr_from_decompile_c(text)
            resolved = header_va or function_addr
            success = (
                "decompile failed" not in text
                and "no function" not in text
                and bool(text.strip())
            )
            if not success and resolved and resolved.lower().removeprefix("0x") != requested_hex:
                text = f"// resolved containing function {resolved}\n" + text
            from ..analysis.verify import parse_function_va

            return {
                "mode": "headless-one-fn",
                "address": parse_function_va(address) or f"0x{requested_hex}",
                "function_addr": resolved,
                "success": success,
                "c": text,
                "returncode": completed.returncode,
                "stderr": (completed.stderr or "")[-800:],
                "stdout": (completed.stdout or "")[-2000:],
            }
        finally:
            Path(output_path).unlink(missing_ok=True)

    def _bridge_deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
    ) -> dict[str, Any]:
        from .ghidra_bridge_client import GhidraBridgeClient

        settings = self.settings or GhidraSettings()
        
        client = GhidraBridgeClient(
            host=settings.bridge_host,
            port=settings.bridge_port,
            timeout=settings.bridge_timeout,
        )
        
        if not client.connect():
            raise AdapterUnavailable("Failed to connect to Ghidra bridge")

        _LOGGER.info("Running Ghidra analysis via bridge for: %s", binary)

        try:
            functions = client.get_functions(limit=200)
            _LOGGER.debug("Retrieved %d functions", len(functions))

            func_addresses = [f["address"] for f in functions if isinstance(f.get("address"), int)]

            decompiled = client.batch_decompile(
                func_addresses, limit=settings.max_decompile_functions
            )
            _LOGGER.debug("Decompiled %d functions", len(decompiled))

            types = client.get_types(limit=settings.max_types)

            strings = client.get_strings(limit=settings.max_strings)

            xref_map = client.get_xrefs_for_functions(func_addresses[:10], limit=10)

            decompiled_data = [
                {
                    "name": d.name,
                    "address": f"0x{d.address:x}",
                    "signature": d.signature,
                    "decompiled_c": d.decompiled_c,
                    "parameters": d.parameters,
                    "return_type": d.return_type,
                    "calling_convention": d.calling_convention,
                }
                for d in decompiled
            ]

            types_data = [
                {
                    "name": t.name,
                    "category": t.category,
                    "size": t.size,
                    "kind": t.kind,
                    "members": t.members,
                }
                for t in types
            ]

            return {
                "mode": "bridge",
                "command": "ghidra_bridge RPC",
                "functions": functions,
                "function_count": len(functions),
                "decompiled": decompiled_data,
                "decompiled_count": len(decompiled_data),
                "types": types_data,
                "type_count": len(types_data),
                "strings": strings,
                "string_count": len(strings),
                "xref_map": xref_map,
                "binary": str(binary),
            }
        finally:
            client.disconnect()

    def _headless_deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
        script: Path | None = None,
        project_name: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if not self.detection.headless_ready:
            raise AdapterUnavailable("Ghidra headless not available")

        project_name = project_name or self.default_project
        script = script or self._script_path("R2BHeadless.java")
        project_dir = Path(self.project_dir).expanduser()
        project_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_path = tmp.name

        command = [
            str(self.detection.headless_path),
            str(project_dir),
            project_name,
            "-import", str(binary),
            "-overwrite",
            "-scriptPath", str(script.parent),
            "-postScript", script.name,
            "-deleteProject",
        ]

        if dry_run:
            return {"command": command, "dry_run": True, "mode": "headless"}

        _LOGGER.info("Running Ghidra headless: %s", " ".join(command))
        
        env = os.environ.copy()
        env["R2B_OUTPUT"] = output_path
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
                env=env,
            )

            ghidra_data: dict[str, Any] = {}
            if Path(output_path).exists():
                try:
                    with open(output_path) as f:
                        ghidra_data = json.load(f)
                    _LOGGER.info("Parsed Ghidra JSON output: %d functions, %d strings",
                                 len(ghidra_data.get("functions", [])),
                                 len(ghidra_data.get("strings", [])))
                except json.JSONDecodeError as e:
                    _LOGGER.warning("Failed to parse Ghidra JSON output: %s", e)

            return {
                "mode": "headless",
                "command": " ".join(command),
                "returncode": result.returncode,
                "success": result.returncode == 0,
                "functions": ghidra_data.get("functions", []),
                "function_count": len(ghidra_data.get("functions", [])),
                "strings": ghidra_data.get("strings", []),
                "string_count": len(ghidra_data.get("strings", [])),
                "decompiled": ghidra_data.get("decompiled", []),
                "decompiled_count": len(ghidra_data.get("decompiled", [])),
                "program": ghidra_data.get("program", {}),
                "stdout": result.stdout.strip()[-2000:] if result.stdout else "",
                "stderr": result.stderr.strip()[-1000:] if result.stderr else "",
            }
        finally:
            try:
                Path(output_path).unlink(missing_ok=True)
            except Exception:
                pass

    def _script_path(self, name: str) -> Path:
        candidates = (
            self.detection.extension_root / "scripts" / name,
            Path(__file__).resolve().parents[1] / "share" / "ghidra" / name,
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        raise AdapterUnavailable(f"Bundled Ghidra script is missing: {name}")

    def close(self) -> None:
        if self._bridge_client:
            self._bridge_client.disconnect()
            self._bridge_client = None
