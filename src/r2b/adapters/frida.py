from __future__ import annotations

import logging
import time
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class FridaAdapter:
    name: str = "frida"
    timeout: int = 10

    @staticmethod
    def _frida() -> types.ModuleType:
        try:
            import frida
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise AdapterUnavailable("frida module is not installed") from exc
        return frida

    def is_available(self) -> bool:
        return self._module_available()

    @staticmethod
    def _module_available() -> bool:
        try:
            import frida  # noqa: F401
        except ModuleNotFoundError:
            return False
        return True

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, object]:
        if not self.is_available():
            raise AdapterUnavailable("frida is not available on this system")

        if not binary.exists():
            return {"error": f"Binary not found: {binary}"}

        if not binary.is_file():
            return {"error": f"Not a file: {binary}"}

        return {
            "available": True,
            "binary": str(binary),
            "note": "Frida requires binary execution for dynamic analysis. Use deep_scan for runtime instrumentation.",
        }

    def deep_scan(self, binary: Path, *, resource_tree: object | None = None, **kwargs: Any) -> dict[str, object]:
        if not self.is_available():
            raise AdapterUnavailable("frida is not available on this system")

        frida = self._frida()

        try:
            _LOGGER.info("Spawning binary for Frida instrumentation: %s", binary)
            pid = frida.spawn(str(binary))
            session = frida.attach(pid)

            script_code = """
            // Enumerate loaded modules
            var modules = Process.enumerateModules();
            var moduleInfo = modules.map(function(m) {
                return {
                    name: m.name,
                    base: m.base.toString(),
                    size: m.size,
                    path: m.path
                };
            });

            // Enumerate exports from main module
            var mainModule = Process.enumerateModules()[0];
            var exports = [];
            if (mainModule) {
                exports = mainModule.enumerateExports().slice(0, 100).map(function(e) {
                    return {
                        type: e.type,
                        name: e.name,
                        address: e.address.toString()
                    };
                });
            }

            // Enumerate imports from main module
            var imports = [];
            if (mainModule) {
                imports = mainModule.enumerateImports().slice(0, 100).map(function(i) {
                    return {
                        type: i.type,
                        name: i.name,
                        module: i.module,
                        address: i.address ? i.address.toString() : null
                    };
                });
            }

            // Get process info
            var processInfo = {
                id: Process.id,
                arch: Process.arch,
                platform: Process.platform,
                pointerSize: Process.pointerSize,
                pageSize: Process.pageSize
            };

            // Send results back
            send({
                modules: moduleInfo,
                exports: exports,
                imports: imports,
                process: processInfo
            });
            """

            result_data: dict[str, Any] = {}
            error_msg: str | None = None

            def on_message(message: dict[str, Any], data: Any) -> None:
                nonlocal result_data, error_msg
                if message.get("type") == "send":
                    result_data = message.get("payload", {})
                elif message.get("type") == "error":
                    error_msg = message.get("description", "Unknown error")
                    _LOGGER.error("Frida script error: %s", error_msg)

            script = session.create_script(script_code)
            script.on("message", on_message)
            script.load()

            frida.resume(pid)

            time.sleep(2)

            try:
                session.detach()
                frida.kill(pid)
            except Exception as e:
                _LOGGER.debug("Failed to kill process cleanly: %s", e)

            if error_msg:
                return {
                    "error": error_msg,
                    "partial_data": result_data,
                }

            return {
                "modules": result_data.get("modules", []),
                "exports": result_data.get("exports", []),
                "imports": result_data.get("imports", []),
                "process_info": result_data.get("process", {}),
                "instrumentation": "success",
            }

        except Exception as exc:
            _LOGGER.exception("Frida deep scan failed: %s", exc)
            return {
                "error": str(exc),
                "note": "Frida requires the binary to be executable. Some binaries may not run due to missing dependencies or architecture mismatch.",
            }
