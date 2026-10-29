from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

from .paths import find_checkout_root, shipped_config_dir

DEFAULT_CONFIG_PATH = shipped_config_dir() / "default_config.toml"
_CHECKOUT_ROOT = find_checkout_root(include_cwd=False)
LOCAL_CONFIG_PATH = (
    _CHECKOUT_ROOT / "config" / "local.toml"
    if _CHECKOUT_ROOT is not None
    else Path("~/.config/r2b/local.toml").expanduser()
)
USER_CONFIG_PATH = Path("~/.config/r2b/config.toml").expanduser()
TRUE_ENV_VALUES = {"1", "true", "yes", "on"}
FALSE_ENV_VALUES = {"0", "false", "no", "off"}


def _get_env(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value
    return None


def _load_implicit_overlays() -> bool:
    if os.getenv("PYTEST_CURRENT_TEST"):
        return False
    parsed = _parse_env_bool(_get_env("R2B_IGNORE_LOCAL") or "")
    if parsed is True:
        return False
    return True


def _parse_env_bool(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in TRUE_ENV_VALUES:
        return True
    if normalized in FALSE_ENV_VALUES:
        return False
    return None


class LLMSettings(BaseModel):
    provider: str = "ollama"
    model: str = "gemma3:4b"
    transport: str = "auto"
    api_key_env: str = ""
    fallback_provider: str | None = "openai"
    fallback_model: str | None = "gpt-5.6-luna"
    fallback_api_key_env: str | None = "OPENAI_API_KEY"
    enable_fallback: bool = False
    max_tokens: int = 8192
    temperature: float = 0.1
    base_url: str = "http://127.0.0.1:11434"
    compact_context: bool = True
    context_budget_chars: int = 24000
    max_tool_rounds: int = Field(default=3, ge=0, le=8)


class ExtractSettings(BaseModel):

    enable: bool = False
    extract_elf: bool = False
    allow_unsafe_fallback: bool = False
    timeout_s: int = 60
    max_files: int = 200
    max_bytes: int = 64 * 1024 * 1024
    max_depth: int = 2


class AnalysisSettings(BaseModel):
    auto_analyze: bool = True
    max_binary_size: str = "200MB"
    enable_angr: bool = False
    enable_ghidra: bool = False
    enable_frida: bool = False
    enable_gef: bool = False
    enable_die: bool = False
    enable_capa: bool = False
    die_timeout_s: int = Field(default=30, ge=1, le=600)
    capa_timeout_s: int = Field(default=120, ge=1, le=3600)
    capa_rules_path: Path | None = None
    gef_timeout: int = 60
    gef_max_instructions: int = 10000
    require_elf: bool = False
    enable_trajectory_recording: bool = True


class OutputSettings(BaseModel):
    format: str = "terminal"
    verbosity: str = "normal"
    save_artifacts: bool = True
    artifacts_dir: Path = Field(default=Path("~/.cache/r2b").expanduser())


class PerformanceSettings(BaseModel):
    parallel_functions: int = 4
    cache_results: bool = True


class StorageSettings(BaseModel):
    database_path: Path = Field(default=Path("~/.local/share/r2b/r2b.db").expanduser())
    auto_migrate: bool = True


class UISettings(BaseModel):
    show_compiler: bool = False


class WebSettings(BaseModel):

    enable_script_execution: bool = False
    enable_native_execution: bool = False
    execution_token_env: str = "R2B_WEB_EXECUTION_TOKEN"


class GhidraSettings(BaseModel):
    use_bridge: bool = False
    bridge_host: str = "127.0.0.1"
    bridge_port: int = 13100
    bridge_timeout: int = 30
    install_dir: Path | None = None
    project_dir: Path = Field(default=Path("~/r2b/ghidra-projects").expanduser())
    max_decompile_functions: int = 20
    max_types: int = 100
    max_strings: int = 200

    @field_validator("project_dir", mode="before")
    @classmethod
    def _expand_project_dir(cls, value: Any) -> Path:
        if value in (None, ""):
            return Path("~/r2b/ghidra-projects").expanduser()
        return Path(str(value)).expanduser()

    @field_validator("install_dir", mode="before")
    @classmethod
    def _expand_install_dir(cls, value: Any) -> Path | None:
        if value in (None, ""):
            return None
        return Path(str(value)).expanduser()



class AppConfig(BaseModel):
    llm: LLMSettings = Field(default_factory=LLMSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    extract: ExtractSettings = Field(default_factory=ExtractSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    performance: PerformanceSettings = Field(default_factory=PerformanceSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    ui: UISettings = Field(default_factory=UISettings)
    web: WebSettings = Field(default_factory=WebSettings)
    ghidra: GhidraSettings = Field(default_factory=GhidraSettings)
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def verbosity(self) -> str:
        return self.output.verbosity


def _load_toml(path: Path) -> dict[str, Any]:
    import tomllib

    with path.open("rb") as fh:
        return tomllib.load(fh)


def apply_lab_tool_path() -> list[Path]:
    extra: list[Path] = []
    raw = _get_env("R2B_TOOL_PATH") or ""
    for part in raw.split(":"):
        text = part.strip()
        if text:
            extra.append(Path(text).expanduser())
    seen: set[str] = set()
    prepend: list[str] = []
    for path in extra:
        resolved = str(path)
        if resolved in seen or not path.is_dir():
            continue
        seen.add(resolved)
        prepend.append(resolved)
    if prepend:
        current = os.environ.get("PATH", "")
        os.environ["PATH"] = ":".join(([current] if current else []) + prepend)
    return [Path(item) for item in prepend]


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: Path | None = None) -> AppConfig:
    load_dotenv()
    apply_lab_tool_path()

    data: dict[str, Any] = {}
    
    if DEFAULT_CONFIG_PATH.exists():
        data = _merge(data, _load_toml(DEFAULT_CONFIG_PATH))

    if _load_implicit_overlays():
        if USER_CONFIG_PATH.exists():
            data = _merge(data, _load_toml(USER_CONFIG_PATH))
        if LOCAL_CONFIG_PATH.exists():
            data = _merge(data, _load_toml(LOCAL_CONFIG_PATH))

    custom_config = config_path
    if custom_config is None:
        env_config = _get_env("R2B_CONFIG")
        if env_config:
            custom_config = Path(env_config).expanduser()

    if custom_config is not None:
        if not custom_config.exists():
            raise FileNotFoundError(
                f"Config file not found: {custom_config} (resolved from cwd {Path.cwd()})"
            )
        data = _merge(data, _load_toml(custom_config))

    config = AppConfig(raw=data)

    if "llm" in data:
        config.llm = LLMSettings.model_validate(data["llm"])
    if "analysis" in data:
        config.analysis = AnalysisSettings.model_validate(data["analysis"])
    if "output" in data:
        config.output = OutputSettings.model_validate(data["output"])
    if "performance" in data:
        config.performance = PerformanceSettings.model_validate(data["performance"])
    if "storage" in data:
        config.storage = StorageSettings.model_validate(data["storage"])
    if "ui" in data:
        config.ui = UISettings.model_validate(data["ui"])
    if "web" in data:
        config.web = WebSettings.model_validate(data["web"])
    if "extract" in data:
        config.extract = ExtractSettings.model_validate(data["extract"])
    if "ghidra" in data:
        ghidra_data = dict(data["ghidra"])
        if ghidra_data.get("install_dir") == "":
            ghidra_data["install_dir"] = None
        config.ghidra = GhidraSettings.model_validate(ghidra_data)
    env_install_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if env_install_dir:
        config.ghidra.install_dir = Path(env_install_dir).expanduser()

    env_api_key = os.getenv(config.llm.api_key_env)
    if env_api_key:
        config.raw.setdefault("llm", {})
        config.raw["llm"]["api_key_present"] = True

    env_show_compiler = _get_env(
        "R2B_SHOW_COMPILER", "r2b_show_compiler"
    )
    if env_show_compiler is not None:
        parsed_show_compiler = _parse_env_bool(env_show_compiler)
        if parsed_show_compiler is not None:
            config.ui.show_compiler = parsed_show_compiler

    env_llm_provider = _get_env("R2B_LLM_PROVIDER")
    if env_llm_provider:
        config.llm.provider = env_llm_provider
    env_llm_model = _get_env("R2B_LLM_MODEL")
    if env_llm_model:
        config.llm.model = env_llm_model
    env_llm_transport = _get_env("R2B_LLM_TRANSPORT")
    if env_llm_transport:
        config.llm.transport = env_llm_transport
    env_llm_base = _get_env("R2B_LLM_BASE_URL")
    if env_llm_base:
        config.llm.base_url = env_llm_base

    from .llm.credentials import apply_provider_defaults

    apply_provider_defaults(config)

    return config
