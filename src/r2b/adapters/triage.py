"""Optional static CLI evidence from Detect It Easy and Mandiant capa.

Keep native JSON intact: rule matches and signatures are tool observations,
not runtime observations or vulnerability verdicts.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable

MAX_REPORT_BYTES = 16 * 1024 * 1024


def _run_json(argv: list[str], timeout_s: int) -> tuple[int, dict[str, Any], str]:
    # Spool output to disk so a verbose analyzer cannot exhaust Python memory.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                timeout=timeout_s, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterUnavailable(f"{Path(argv[0]).name}: {exc}") from exc
        stderr.seek(0)
        diagnostic = stderr.read(4096).decode("utf-8", errors="replace").strip()
        if stdout.tell() > MAX_REPORT_BYTES:
            raise AdapterUnavailable("Analyzer JSON exceeds the 16 MiB report limit")
        stdout.seek(0)
        data = stdout.read()
    if completed.returncode and not data.strip():
        return completed.returncode, {}, diagnostic
    try:
        payload = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise AdapterUnavailable(f"Analyzer returned invalid JSON: {diagnostic}") from exc
    if not isinstance(payload, dict):
        raise AdapterUnavailable("Analyzer JSON must be an object")
    return completed.returncode, payload, diagnostic


@dataclass(slots=True)
class DetectItEasyAdapter:
    name: str = "die"
    timeout_s: int = 30

    def is_available(self) -> bool:
        return shutil.which("diec") is not None

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        executable = shutil.which("diec")
        if not executable:
            raise AdapterUnavailable("Detect It Easy CLI (diec) is not on PATH")
        argv = [executable, "--json", str(binary.resolve())]
        code, report, diagnostic = _run_json(argv, self.timeout_s)
        if code:
            raise AdapterUnavailable(f"diec exited {code}: {diagnostic}")
        if not isinstance(report.get("detects"), list):
            raise AdapterUnavailable("Unrecognized diec JSON: expected detects list")
        detections = []
        for detection in report["detects"]:
            if not isinstance(detection, dict):
                continue
            for value in detection.get("values", []):
                if isinstance(value, dict):
                    detections.append({
                        "type": value.get("type"), "name": value.get("name"),
                        "version": value.get("version"), "info": value.get("info"),
                        "filetype": detection.get("filetype"),
                    })
        return {"status": "completed", "evidence_kind": "identification",
                "detections": detections[:100], "detection_count": len(detections),
                "report": report, "command": argv,
                "warnings": [diagnostic] if diagnostic else []}

    def deep_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        return self.quick_scan(binary)


@dataclass(slots=True)
class CapaAdapter:
    name: str = "capa"
    timeout_s: int = 120
    rules_path: Path | None = None

    def is_available(self) -> bool:
        return shutil.which("capa") is not None

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        return {"status": "skipped", "reason": "capa runs in the deep stage"}

    def deep_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        executable = shutil.which("capa")
        if not executable:
            raise AdapterUnavailable("Mandiant capa CLI is not on PATH")
        argv = [executable, "--json"]
        if self.rules_path:
            argv.extend(["--rules", str(self.rules_path.expanduser().resolve())])
        argv.append(str(binary.resolve()))
        code, report, diagnostic = _run_json(argv, self.timeout_s)
        if code in {16, 17, 18}:
            return {"status": "skipped", "reason": diagnostic or
                    "capa does not support this format, architecture, or OS", "command": argv}
        if code not in {0, 14}:
            raise AdapterUnavailable(f"capa exited {code}: {diagnostic}")
        if not isinstance(report.get("rules"), dict) or not isinstance(report.get("meta"), dict):
            raise AdapterUnavailable("Unrecognized capa JSON: expected meta and rules objects")
        capabilities = []
        for name, rule in sorted(report["rules"].items()):
            if not isinstance(rule, dict):
                continue
            meta = rule.get("meta") or {}
            if meta.get("lib") or meta.get("capa/subscope"):
                continue
            matches = rule.get("matches") or []
            capabilities.append({
                "name": name, "namespace": meta.get("namespace"),
                "scopes": meta.get("scopes"),
                "locations": [match[0] for match in matches[:20]
                              if isinstance(match, list) and len(match) == 2],
                "match_count": len(matches),
                "report_ref": "/rules/" + name.replace("~", "~0").replace("/", "~1"),
            })
        warnings = [diagnostic] if diagnostic else []
        if code == 14:
            warnings.append("capa reported a static analysis limitation; results are incomplete")
        return {"status": "partial" if code == 14 else "completed",
                "evidence_kind": "capability_rule_match",
                "capabilities": capabilities[:100], "capability_count": len(capabilities),
                "report": report, "command": argv, "warnings": warnings}
