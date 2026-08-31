from pathlib import Path

from r2b.environment.setup import HostFacts, recommend_flavor, recommend_setup

ROOT = Path(__file__).resolve().parents[2]


def _facts(**overrides: object) -> HostFacts:
    base = dict(
        os="linux",
        arch="aarch64",
        ram_gb=7.5,
        cpus=4,
        python="3.11.13",
        uv=True,
        docker=False,
        node=False,
        likely_pi=True,
        tools={"radare2": True, "file": True, "binwalk3": False, "ghidra": False},
    )
    base.update(overrides)
    return HostFacts(**base)  # type: ignore[arg-type]


def test_pi_box_gets_core_and_skips_ghidra_angr() -> None:
    plan = recommend_setup(facts=_facts())
    assert plan["schema_version"] == "r2b.setup.v1"
    assert plan["flavor"] == "core"
    assert plan["uv_extra"] == "r2"
    skip_names = {row["name"] for row in plan["skip"]}
    assert "ghidra" in skip_names
    assert "angr" in skip_names
    assert any("uv sync --extra r2" == c for c in plan["commands"])
    assert "verify" in plan["agent"]["verbs"]
    assert plan["agent"]["empty_ask_exit"] == 2
    assert any("--extra llm" in note for note in plan["notes"])


def test_x86_16gb_gets_full() -> None:
    facts = _facts(
        arch="x86_64",
        ram_gb=32,
        likely_pi=False,
        docker=True,
        node=True,
        tools={"radare2": True, "file": True, "binwalk3": True, "ghidra": True},
    )
    assert recommend_flavor(facts) == "full"
    plan = recommend_setup(facts=facts)
    assert plan["flavor"] == "full"
    assert plan["uv_extra"] == "analyzers"


def test_mid_ram_workstation_is_lab() -> None:
    facts = _facts(arch="x86_64", ram_gb=12, likely_pi=False, docker=True)
    assert recommend_flavor(facts) == "lab"
    plan = recommend_setup(facts=facts)
    assert plan["uv_extra"] == "r2"
    assert "binwalk3" in plan["apt"]


def test_flavor_override_does_not_change_recommended() -> None:
    facts = _facts()
    plan = recommend_setup(facts=facts, flavor="lab")
    assert plan["flavor"] == "lab"
    assert plan["recommended_flavor"] == "core"


def test_missing_r2_is_a_missing_row() -> None:
    facts = _facts(tools={"radare2": False, "file": True})
    plan = recommend_setup(facts=facts)
    assert any(row["name"] == "radare2" for row in plan["missing"])


def test_commands_do_not_sudo_or_write_config_when_tools_present() -> None:
    plan = recommend_setup(facts=_facts())
    assert not any(cmd.startswith("sudo") for cmd in plan["commands"])
    assert not any("|| cp " in cmd for cmd in plan["commands"])


def test_darwin_lab_never_emits_linux_package_commands() -> None:
    facts = _facts(
        os="darwin",
        arch="arm64",
        ram_gb=24,
        likely_pi=False,
        node=True,
        tools={"radare2": True, "file": True, "binwalk3": False, "ghidra": False},
    )

    plan = recommend_setup(facts=facts)

    assert plan["flavor"] == "lab"
    assert not any("apt-get" in cmd for cmd in plan["commands"])
    assert not any(row["name"] == "ghidra" for row in plan["skip"])
    assert any("r2b ghidra setup" in note for note in plan["notes"])


def test_optional_extractor_does_not_trigger_system_install() -> None:
    facts = _facts(
        arch="x86_64",
        ram_gb=16,
        likely_pi=False,
        tools={"radare2": True, "file": True, "binwalk3": False, "ghidra": False},
    )

    plan = recommend_setup(facts=facts, flavor="lab")

    assert not any("apt-get" in cmd for cmd in plan["commands"])
    assert any("binwalk3 missing" in note for note in plan["notes"])


def test_flavor_overlays_exist() -> None:
    for name in ("core", "lab", "full"):
        path = ROOT / "config" / "flavors" / f"{name}.toml"
        assert path.is_file(), path
        assert "[analysis]" in path.read_text(encoding="utf-8")
