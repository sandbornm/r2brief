"""Guards for the frontend toolchain pins that broke Dependabot #28."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "web" / "frontend"


def _parse(version: str) -> tuple[int, int, int]:
    core = version.strip().lstrip("v").split("-", 1)[0]
    parts = [int(piece) for piece in core.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def _bump(version: tuple[int, int, int]) -> tuple[int, int, int]:
    return (version[0], version[1], version[2] + 1)


def _satisfies_atom(version: str, atom: str) -> bool:
    current = _parse(version)
    if atom.startswith(">="):
        return current >= _parse(atom[2:])
    if atom.startswith("<="):
        return current <= _parse(atom[2:])
    if atom.startswith(">"):
        return current > _parse(atom[1:])
    if atom.startswith("<"):
        return current < _parse(atom[1:])
    if atom.startswith("^"):
        base = _parse(atom[1:])
        upper = (base[0] + 1, 0, 0) if base[0] > 0 else (0, base[1] + 1, 0)
        return base <= current < upper
    if atom.startswith("~"):
        base = _parse(atom[1:])
        return base <= current < (base[0], base[1] + 1, 0)
    if atom == "*":
        return True
    return current == _parse(atom)


def satisfies(version: str, range_spec: str) -> bool:
    for alternative in range_spec.split("||"):
        atoms = alternative.split()
        if atoms and all(_satisfies_atom(version, atom) for atom in atoms):
            return True
    return False


def minimum_node_22(range_spec: str) -> tuple[int, int, int] | None:
    """Smallest Node 22 version accepted by an engines range, if any."""
    found: list[tuple[int, int, int]] = []
    for alternative in range_spec.split("||"):
        low = (22, 0, 0)
        high = (23, 0, 0)
        possible = True
        for atom in alternative.split():
            if atom.startswith(">="):
                bound = _parse(atom[2:])
                if bound >= high:
                    possible = False
                    break
                if bound > low:
                    low = bound
            elif atom.startswith(">"):
                bound = _bump(_parse(atom[1:]))
                if bound >= high:
                    possible = False
                    break
                if bound > low:
                    low = bound
            elif atom.startswith("<="):
                bound = _bump(_parse(atom[2:]))
                if bound <= low:
                    possible = False
                    break
                if bound < high:
                    high = bound
            elif atom.startswith("<"):
                bound = _parse(atom[1:])
                if bound <= low:
                    possible = False
                    break
                if bound < high:
                    high = bound
            elif atom.startswith("^"):
                base = _parse(atom[1:])
                upper = (base[0] + 1, 0, 0) if base[0] > 0 else (0, base[1] + 1, 0)
                if base > low:
                    low = base
                if upper < high:
                    high = upper
                if low >= high:
                    possible = False
                    break
            elif atom.startswith("~"):
                base = _parse(atom[1:])
                upper = (base[0], base[1] + 1, 0)
                if base > low:
                    low = base
                if upper < high:
                    high = upper
                if low >= high:
                    possible = False
                    break
            else:
                exact = _parse(atom)
                if not (low <= exact < high):
                    possible = False
                    break
                low = exact
                high = _bump(exact)
        if possible and low[0] == 22 and low < high:
            found.append(low)
    return min(found) if found else None


def _lock() -> dict:
    return json.loads((FRONTEND / "package-lock.json").read_text())


def _pkg() -> dict:
    return json.loads((FRONTEND / "package.json").read_text())


def _locked(name: str) -> dict:
    entry = _lock()["packages"].get(f"node_modules/{name}")
    assert entry is not None, name
    return entry


def test_node_range_helper_matches_known_engines() -> None:
    assert minimum_node_22("^20.19.0 || >=22.12.0") == (22, 12, 0)
    assert minimum_node_22("^22.22.2 || ^24.15.0 || >=26.0.0") == (22, 22, 2)
    assert minimum_node_22("^22.12.0 || ^24.0.0 || >=26.0.0") == (22, 12, 0)
    assert minimum_node_22(">=18") == (22, 0, 0)
    assert minimum_node_22(">=24") is None
    assert satisfies("6.0.3", ">=4.8.4 <6.1.0")
    assert not satisfies("7.0.2", ">=4.8.4 <6.1.0")
    assert not satisfies("7.0.2", ">=6.0.3 <6.1.0")


def test_node_22_declarations_agree() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    dockerfile = (ROOT / "Dockerfile.frontend").read_text()
    setup = (ROOT / "scripts" / "setup_frontend.sh").read_text()
    checker = (ROOT / "scripts" / "frontend_node_range.mjs").read_text()
    nvmrc = (FRONTEND / ".nvmrc").read_text().strip()
    pkg = _pkg()
    engines = pkg["engines"]["node"]
    jsdom_engines = _locked("jsdom")["engines"]["node"]

    image = re.search(r"^FROM node:(\S+)", dockerfile, re.M)
    assert image is not None
    image_node = image.group(1).split("-", 1)[0]
    range_match = re.search(r"FRONTEND_NODE_RANGE = '([^']+)'", checker)
    assert range_match is not None
    node_range = range_match.group(1)

    assert re.fullmatch(r"22\.\d+\.\d+", nvmrc)
    assert nvmrc == image_node
    assert "node-version-file: web/frontend/.nvmrc" in ci
    assert "node-version-file: web/frontend/.nvmrc" in release
    assert "node-version:" not in ci.replace("node-version-file:", "")
    assert "node-version:" not in release.replace("node-version-file:", "")
    assert "npm run typecheck" in ci
    assert "npm run typecheck" in release
    assert node_range == jsdom_engines
    assert engines == node_range
    assert _lock()["packages"][""]["engines"]["node"] == node_range
    assert satisfies(nvmrc, engines)
    assert satisfies(nvmrc, node_range)
    for rejected in ("23.0.0", "24.14.9", "25.0.0"):
        assert not satisfies(rejected, engines)
    assert "frontend_node_range.mjs" in setup
    assert "major > 22" not in setup

    floor = _parse(nvmrc)
    direct = {**pkg["dependencies"], **pkg["devDependencies"]}
    for name in direct:
        spec = _lock()["packages"].get(f"node_modules/{name}", {}).get("engines", {}).get("node")
        if not spec:
            continue
        required = minimum_node_22(spec)
        assert required is not None, f"{name} engines {spec} reject Node 22"
        assert floor >= required, (name, spec, floor, required)


def test_frontend_node_range_boundaries() -> None:
    script = ROOT / "scripts" / "frontend_node_range.mjs"
    cases = {
        "22.22.1": False,
        "22.22.2": True,
        "22.23.4": True,
        "23.0.0": False,
        "24.14.9": False,
        "24.15.0": True,
        "24.99.0": True,
        "25.0.0": False,
        "25.9.1": False,
        "26.0.0": True,
        "27.1.0": True,
    }
    for version, accepted in cases.items():
        result = subprocess.run(
            ["node", str(script), version],
            check=False,
            capture_output=True,
            text=True,
        )
        assert (result.returncode == 0) is accepted, (version, result.returncode, result.stderr)


def test_typescript_stays_inside_typescript_eslint_peer() -> None:
    pkg = _pkg()
    locked = _locked("typescript")["version"]
    peer = _locked("@typescript-eslint/eslint-plugin")["peerDependencies"]["typescript"]
    requested = pkg["devDependencies"]["typescript"]

    assert satisfies(locked, peer), (locked, peer)
    assert satisfies(locked, requested)
    assert not satisfies("7.0.2", peer)
    assert not satisfies("7.0.2", requested)
    assert _parse(locked) >= (6, 0, 3)
    assert _parse(locked) < (6, 1, 0)

    for relative in ("tsconfig.json", "tsconfig.node.json"):
        config = json.loads((FRONTEND / relative).read_text())
        assert config["compilerOptions"]["moduleResolution"] == "bundler"


def test_eslint_flat_config_replaces_eslintrc() -> None:
    config = (FRONTEND / "eslint.config.js").read_text()
    assert "typescript-eslint" in config
    assert "@eslint/js" in config
    assert not (FRONTEND / ".eslintrc.cjs").exists()
    assert not (FRONTEND / ".eslintrc.js").exists()
    assert "eslint-plugin-react" not in _pkg()["devDependencies"]
    assert "@eslint/js" in _pkg()["devDependencies"]
    assert "eslint-plugin-react-hooks" in _pkg()["devDependencies"]
    assert "eslint-plugin-react-x" in _pkg()["devDependencies"]
    assert "react-hooks/rules-of-hooks" in config
    assert "react-x/no-missing-key" in config
    eslint_version = _locked("eslint")["version"]
    assert _parse(eslint_version)[0] == 10
    for plugin in ("eslint-plugin-react-hooks", "eslint-plugin-react-x"):
        peer = _locked(plugin)["peerDependencies"]["eslint"]
        assert satisfies(eslint_version, peer), (plugin, peer)
    assert _parse(_locked("@eslint/js")["version"])[0] == 10
    env = (FRONTEND / "src" / "vite-env.d.ts").read_text()
    assert "vite/client" in env


def test_mui_stays_on_v5_with_react_19_peers() -> None:
    pkg = _pkg()
    for name in ("@mui/material", "@mui/icons-material"):
        spec = pkg["dependencies"][name]
        assert spec.startswith("^5.")
        assert _parse(spec[1:]) >= (5, 16, 12)
        locked = _parse(_locked(name)["version"])
        assert locked[0] == 5
        assert locked >= (5, 16, 12)


def test_vite_unwraps_prebundled_mui_icon_defaults() -> None:
    config = (FRONTEND / "vite.config.ts").read_text()
    helper = (FRONTEND / "src" / "muiIconInterop.ts").read_text()
    rewrite = (FRONTEND / "muiIconRewrite.ts").read_text()
    assert "mui-icon-default-interop" in config
    assert "rewriteMuiIconImports" in config
    assert "isAppSourceModule" in config
    assert "path.sep" not in config
    assert "exclude: ['@mui/icons-material']" not in config
    assert "function muiIconComponent" in helper
    assert "imported.default" in helper or "current.default" in helper
    assert "isNamedImports" in rewrite
    assert "isNamespaceImport" in rewrite
    assert "replace(/\\\\/g, '/')" in rewrite


def test_dependabot_majors_that_resolve_are_locked() -> None:
    expected = {
        "react": 19,
        "react-dom": 19,
        "@types/react": 19,
        "@types/react-dom": 19,
        "react-markdown": 10,
        "@testing-library/react": 16,
        "@testing-library/jest-dom": 7,
        "jsdom": 30,
        "vitest": 5,
        "@typescript-eslint/eslint-plugin": 8,
        "@typescript-eslint/parser": 8,
    }
    for name, major in expected.items():
        assert _parse(_locked(name)["version"])[0] == major
