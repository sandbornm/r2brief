from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..config import AppConfig

GHIDRA_MIN_VERSION = "10.4"


@dataclass(slots=True)
class GhidraDetection:
    install_dir: Path | None
    headless_path: Path | None
    bridge_available: bool
    bridge_connected: bool
    extension_root: Path
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    bridge_program_loaded: str | None = None

    @property
    def is_ready(self) -> bool:
        return self.headless_path is not None

    @property
    def headless_ready(self) -> bool:
        return self.headless_path is not None

    @property
    def bridge_ready(self) -> bool:
        return self.bridge_available and self.bridge_connected and self.bridge_program_loaded is not None


def detect_ghidra(config: AppConfig, project_root: Path | None = None) -> GhidraDetection:
    project_root = project_root or Path(__file__).resolve().parents[3]
    extension_root = project_root / "ghidra" / "extensions" / "r2b"

    configured_dir = config.ghidra.install_dir
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR")

    install_dir: Path | None = None
    if configured_dir and Path(configured_dir).expanduser().exists():
        install_dir = Path(configured_dir).expanduser()
    elif env_dir and Path(env_dir).expanduser().exists():
        install_dir = Path(env_dir).expanduser()

    path_headless = shutil.which("analyzeHeadless")
    path_ghidra_run = shutil.which("ghidraRun")
    if install_dir is None and path_headless:
        headless_candidate = Path(path_headless).resolve()
        install_dir = headless_candidate.parent.parent
    elif install_dir is None and path_ghidra_run:
        run_candidate = Path(path_ghidra_run).resolve()
        candidate_root = run_candidate.parent
        if (candidate_root / "support" / "analyzeHeadless").is_file():
            install_dir = candidate_root

    headless_path: Path | None = None
    issues: list[str] = []
    notes: list[str] = []

    if install_dir:
        script_name = "analyzeHeadless.bat" if platform.system() == "Windows" else "analyzeHeadless"
        candidate = install_dir / "support" / script_name
        if candidate.exists():
            headless_path = candidate
            notes.append(f"Ghidra headless ready: {candidate}")
        else:
            issues.append("analyzeHeadless not found in Ghidra install.")
    else:
        notes.append(
            "Ghidra skipped (optional). Set GHIDRA_INSTALL_DIR only when you want decompile."
        )

    bridge_available = False
    bridge_connected = False
    bridge_program_loaded: str | None = None

    if config.ghidra.use_bridge:
        try:
            import ghidra_bridge  # noqa: F401
            bridge_available = True
            
            try:
                from ..adapters.ghidra_bridge_client import GhidraBridgeClient
                client = GhidraBridgeClient(
                    host=config.ghidra.bridge_host,
                    port=config.ghidra.bridge_port,
                    timeout=5,
                )
                if client.connect():
                    bridge_program_loaded = client.get_current_program_name()
                    if bridge_program_loaded:
                        bridge_connected = True
                        notes.append(f"Bridge active: {bridge_program_loaded}")
                    client.disconnect()
            except Exception:
                pass
                
        except ImportError:
            pass

    return GhidraDetection(
        install_dir=install_dir,
        headless_path=headless_path,
        bridge_available=bridge_available,
        bridge_connected=bridge_connected,
        extension_root=extension_root,
        issues=issues,
        notes=notes,
        bridge_program_loaded=bridge_program_loaded,
    )


def extension_build_command(detection: GhidraDetection) -> list[str]:
    gradle_cmd = "gradle"
    if platform.system() == "Windows":
        gradle_cmd = "gradlew.bat"

    return [
        gradle_cmd,
        "-PGHIDRA_INSTALL_DIR=" + (str(detection.install_dir) if detection.install_dir else ""),
        "build",
    ]
