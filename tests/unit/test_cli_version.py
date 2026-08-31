from typer.testing import CliRunner

from r2b.cli import app
from r2b import __version__


def test_cli_version_prints_package_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__
    assert __version__


def test_pyproject_version_is_semver_taggable() -> None:
    import pathlib
    import re
    import tomllib

    version = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version


def test_console_scripts_ship_r2b_with_r2b_alias() -> None:
    import pathlib
    import tomllib

    scripts = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["scripts"]
    assert scripts["r2b"] == "r2b.cli:run"
    assert scripts["r2b-web"] == "r2b.web.server:run"
    assert scripts["r2b"] == "r2b.cli:run"
    assert scripts["r2b-web"] == "r2b.web.server:run"


def test_default_deps_are_cli_only() -> None:
    import pathlib
    import tomllib

    data = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
    required = " ".join(data["project"]["dependencies"]).lower()
    for banned in ("flask", "openai", "anthropic", "ghidra-bridge"):
        assert banned not in required, banned
    extras = data["project"]["optional-dependencies"]
    assert "openai" in " ".join(extras["llm"]).lower()
    assert "flask" in " ".join(extras["web"]).lower()
    std = " ".join(extras["std"]).lower()
    assert "r2pipe" in std and "flask" in std and "openai" in std
    assert extras["ghidra"]
    assert not any("git+" in dep for rows in extras.values() for dep in rows)
    force = data["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert not any("local.toml" in str(src) or "local.toml" in str(dst) for src, dst in force.items())
    assert "r2b/share/default_config.toml" in force.values()
    assert pathlib.Path("web/frontend/dist/.gitkeep").is_file()
    dev = " ".join(data["dependency-groups"]["dev"]).lower()
    assert "r2pipe" in dev and "flask" in dev and "pytest" in dev
