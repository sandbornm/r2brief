"""Guards for the frontend toolchain pins that broke Dependabot #28."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

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
    setup = (ROOT / "scripts" / "setup_frontend.sh").read_text()
    checker = (ROOT / "scripts" / "frontend_node_range.mjs").read_text()
    nvmrc = (FRONTEND / ".nvmrc").read_text().strip()
    pkg = _pkg()
    engines = pkg["engines"]["node"]
    jsdom_engines = _locked("jsdom")["engines"]["node"]

    frontend_images: dict[str, list[str]] = {}
    for path in sorted(ROOT.glob("Dockerfile*")):
        text = path.read_text()
        if "web/frontend" not in text or "npm " not in text:
            continue
        images = re.findall(r"^FROM node:(\S+)", text, re.M)
        assert images, f"{path.name} installs the frontend without a Node image"
        frontend_images[path.name] = images
    assert set(frontend_images) == {"Dockerfile.frontend", "Dockerfile.backend"}
    for name, images in frontend_images.items():
        for image in images:
            assert image.split("-", 1)[0] == nvmrc, (name, image)
            assert not image.startswith("20"), (name, image)

    range_match = re.search(r"FRONTEND_NODE_RANGE = '([^']+)'", checker)
    assert range_match is not None
    node_range = range_match.group(1)

    assert re.fullmatch(r"22\.\d+\.\d+", nvmrc)
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


def _workflow_jobs(text: str) -> dict[str, str]:
    lines = text.splitlines()
    start = lines.index("jobs:")
    jobs: dict[str, str] = {}
    name: str | None = None
    buf: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line.startswith(" "):
            break
        if re.fullmatch(r"  [A-Za-z0-9_-]+:", line):
            if name is not None:
                jobs[name] = "\n".join(buf)
            name = line.strip()[:-1]
            buf = []
            continue
        if name is not None:
            buf.append(line)
    if name is not None:
        jobs[name] = "\n".join(buf)
    return jobs


def _job_steps(job: str) -> list[str]:
    steps: list[str] = []
    current: list[str] | None = None
    in_steps = False
    for line in job.splitlines():
        if re.fullmatch(r"    steps:", line):
            in_steps = True
            continue
        if not in_steps:
            continue
        if re.fullmatch(r"    [A-Za-z0-9_-]+:", line):
            break
        if line.startswith("      - "):
            if current is not None:
                steps.append("\n".join(current))
            current = [line]
            continue
        if current is not None:
            current.append(line)
    if current is not None:
        steps.append("\n".join(current))
    return steps


def _script_installs_frontend(relative: str) -> bool:
    path = ROOT / relative
    if not path.is_file():
        return False
    text = path.read_text()
    return "web/frontend" in text and re.search(r"\bnpm\s+", text) is not None


def _run_script(step: str) -> str:
    block = re.search(r"(?m)^[ ]*run:[ ]*\|[ ]*$", step)
    if block:
        return step[block.end() :]
    inline = re.search(r"(?m)^[ ]*run:[ ]*(\S.*?)\s*$", step)
    return inline.group(1) if inline else ""


def _step_runs_frontend_npm(step: str, job_wd: str | None) -> bool:
    script = _run_script(step)
    if not script:
        return False
    for relative in re.findall(r"(?:\./)?(scripts/[\w./-]+\.sh)", script):
        if _script_installs_frontend(relative):
            return True
    wd_match = re.search(r"working-directory:\s*(\S+)", step)
    wd = wd_match.group(1) if wd_match else job_wd
    runs_npm = re.search(r"(?m)^\s*npm\s+", script) is not None
    return runs_npm and (wd == "web/frontend" or "web/frontend" in script)


def _step_uses_nvmrc(step: str) -> bool:
    return "actions/setup-node@" in step and "node-version-file: web/frontend/.nvmrc" in step


def test_frontend_npm_jobs_use_nvmrc() -> None:
    """SKIP_FRONTEND does not skip npm: package_release.sh always builds web/frontend."""
    workflows = {
        "ci.yml": ROOT / ".github" / "workflows" / "ci.yml",
        "release.yml": ROOT / ".github" / "workflows" / "release.yml",
    }
    covered: set[tuple[str, str]] = set()
    for workflow, path in workflows.items():
        for name, job in _workflow_jobs(path.read_text()).items():
            header = job.split("steps:", 1)[0]
            wd_match = re.search(r"working-directory:\s*(\S+)", header)
            job_wd = wd_match.group(1) if wd_match else None
            steps = _job_steps(job)
            npm_at = [index for index, step in enumerate(steps) if _step_runs_frontend_npm(step, job_wd)]
            if not npm_at:
                continue
            covered.add((workflow, name))
            setup_at = [index for index, step in enumerate(steps) if _step_uses_nvmrc(step)]
            assert setup_at, f"{workflow} job {name} runs frontend npm without setup-node"
            assert min(setup_at) < min(npm_at), f"{workflow} job {name} sets up Node after npm"

    assert covered == {("ci.yml", "frontend"), ("ci.yml", "package"), ("release.yml", "release")}


def _step_runs_node_range_test(step: str) -> bool:
    script = _run_script(step)
    if re.search(r"\bpytest\b", script) is None:
        return False
    return any(
        token in script
        for token in ("tests/unit", "test_frontend_toolchain", "test_frontend_node_range_boundaries")
    )


def test_node_range_pytest_jobs_use_nvmrc() -> None:
    workflows = {
        "ci.yml": ROOT / ".github" / "workflows" / "ci.yml",
        "release.yml": ROOT / ".github" / "workflows" / "release.yml",
    }
    covered: set[tuple[str, str]] = set()
    for workflow, path in workflows.items():
        for name, job in _workflow_jobs(path.read_text()).items():
            steps = _job_steps(job)
            pytest_at = [index for index, step in enumerate(steps) if _step_runs_node_range_test(step)]
            if not pytest_at:
                continue
            covered.add((workflow, name))
            setup_at = [index for index, step in enumerate(steps) if _step_uses_nvmrc(step)]
            assert setup_at, f"{workflow} job {name} runs the node-range pytest without setup-node"
            assert min(setup_at) < min(pytest_at), f"{workflow} job {name} sets up Node after pytest"
    assert covered == {("ci.yml", "backend"), ("release.yml", "release")}


def test_frontend_node_range_boundaries() -> None:
    if shutil.which("node") is None:
        pytest.skip("node is not installed")
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
