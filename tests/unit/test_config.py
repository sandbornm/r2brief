"""Unit tests for configuration module."""

from pathlib import Path
from unittest.mock import patch
import os

import pytest

from r2b.config import (
    AppConfig,
    AnalysisSettings,
    DEFAULT_CONFIG_PATH,
    ExtractSettings,
    LLMSettings,
    apply_lab_tool_path,
    StorageSettings,
    UISettings,
    GhidraSettings,
    OutputSettings,
    PerformanceSettings,
    load_config,
    _merge,
)
from r2b.paths import find_checkout_root, shipped_config_dir


class TestAppConfig:
    """Tests for AppConfig."""

    def test_default_config_has_expected_structure(self):
        """Test default AppConfig has all expected sections."""
        config = AppConfig()

        assert isinstance(config.llm, LLMSettings)
        assert isinstance(config.analysis, AnalysisSettings)
        assert isinstance(config.storage, StorageSettings)
        assert isinstance(config.ui, UISettings)
        assert isinstance(config.ghidra, GhidraSettings)
        assert isinstance(config.output, OutputSettings)
        assert isinstance(config.performance, PerformanceSettings)
        assert isinstance(config.extract, ExtractSettings)
        assert config.extract.enable is False
        assert config.extract.extract_elf is False
        assert config.extract.allow_unsafe_fallback is False
        assert config.web.enable_script_execution is False
        assert config.web.enable_native_execution is False

    def test_verbosity_property_returns_output_verbosity(self):
        """Test verbosity property delegates to output.verbosity."""
        config = AppConfig()
        config.output.verbosity = "debug"

        assert config.verbosity == "debug"


class TestLLMSettings:
    """Tests for LLMSettings."""

    def test_default_values(self):
        """Test LLMSettings has sensible defaults."""
        settings = LLMSettings()

        assert settings.provider == "ollama"
        assert settings.model == "gemma3:4b"
        assert settings.base_url == "http://127.0.0.1:11434"
        assert settings.compact_context is True
        assert settings.enable_fallback is False  # Disabled by default
        assert settings.max_tokens > 0
        assert 0 <= settings.temperature <= 1

    def test_custom_values(self):
        """Test LLMSettings accepts custom values."""
        settings = LLMSettings(
            provider="openai",
            model="gpt-5.6-luna",
            enable_fallback=False,
            max_tokens=4096,
            temperature=0.5,
        )

        assert settings.provider == "openai"
        assert settings.model == "gpt-5.6-luna"
        assert settings.enable_fallback is False
        assert settings.max_tokens == 4096


class TestAnalysisSettings:
    """Tests for AnalysisSettings."""

    def test_default_values(self):
        """Test AnalysisSettings has sensible defaults."""
        settings = AnalysisSettings()

        assert settings.auto_analyze is True
        assert settings.require_elf is False
        assert settings.max_binary_size == "200MB"
        assert settings.enable_angr is False
        assert settings.enable_ghidra is False

    def test_disable_adapters(self):
        """Test adapters can be disabled."""
        settings = AnalysisSettings(
            enable_angr=False,
            enable_ghidra=False,
        )

        assert settings.enable_angr is False
        assert settings.enable_ghidra is False


class TestStorageSettings:
    """Tests for StorageSettings."""

    def test_default_database_path(self):
        """Test default database path is in user's data directory."""
        settings = StorageSettings()

        assert isinstance(settings.database_path, Path)
        assert "r2b" in str(settings.database_path)

    def test_custom_database_path(self, tmp_path):
        """Test custom database path can be set."""
        custom_path = tmp_path / "custom.db"
        settings = StorageSettings(database_path=custom_path)

        assert settings.database_path == custom_path


class TestUISettings:
    """Tests for UI feature flags."""

    def test_compiler_hidden_by_default(self):
        settings = UISettings()

        assert settings.show_compiler is False


class TestGhidraSettings:
    """Tests for GhidraSettings."""

    def test_default_values(self):
        """Test GhidraSettings has sensible defaults."""
        settings = GhidraSettings()

        assert settings.use_bridge is False
        assert settings.bridge_host == "127.0.0.1"
        assert settings.bridge_port == 13100
        assert settings.install_dir is None

    def test_bridge_configuration(self):
        """Test bridge settings can be configured."""
        settings = GhidraSettings(
            use_bridge=True,
            bridge_host="192.168.1.1",
            bridge_port=9999,
        )

        assert settings.use_bridge is True
        assert settings.bridge_host == "192.168.1.1"
        assert settings.bridge_port == 9999



class TestMerge:
    """Tests for _merge function."""

    def test_merge_flat_dicts(self):
        """Test merging flat dictionaries."""
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _merge(base, override)

        assert result == {"a": 1, "b": 3, "c": 4}

    def test_merge_nested_dicts(self):
        """Test merging nested dictionaries."""
        base = {"outer": {"a": 1, "b": 2}}
        override = {"outer": {"b": 3, "c": 4}}
        result = _merge(base, override)

        assert result == {"outer": {"a": 1, "b": 3, "c": 4}}

    def test_merge_preserves_base(self):
        """Test merge doesn't modify base dictionary."""
        base = {"a": 1}
        override = {"a": 2}
        _merge(base, override)

        assert base == {"a": 1}

    def test_merge_deeply_nested(self):
        """Test merging deeply nested structures."""
        base = {"l1": {"l2": {"l3": {"a": 1}}}}
        override = {"l1": {"l2": {"l3": {"b": 2}}}}
        result = _merge(base, override)

        assert result == {"l1": {"l2": {"l3": {"a": 1, "b": 2}}}}


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_config_returns_app_config(self):
        """Test load_config returns an AppConfig instance."""
        config = load_config()

        assert isinstance(config, AppConfig)

    def test_load_config_from_custom_path(self, tmp_path):
        """Test load_config loads from custom path."""
        config_path = tmp_path / "custom_config.toml"
        config_path.write_text("""
[llm]
model = "test-model"

[analysis]
max_binary_size = "10MB"
""")

        config = load_config(config_path)

        assert config.llm.model == "test-model"
        assert config.analysis.max_binary_size == "10MB"

    def test_load_config_honors_env_ghidra_dir(self, tmp_path):
        """Test GHIDRA_INSTALL_DIR env var is honored."""
        ghidra_dir = str(tmp_path / "ghidra")

        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": ghidra_dir}):
            config = load_config()

            assert config.ghidra.install_dir == Path(ghidra_dir)

    def test_load_config_honors_show_compiler_env_bool(self):
        """Test show_compiler accepts compact boolean environment values."""
        with patch.dict(os.environ, {"R2B_SHOW_COMPILER": "1"}, clear=True):
            config = load_config()

            assert config.ui.show_compiler is True

    def test_load_config_honors_lowercase_show_compiler_env(self):
        """Test shell-friendly lowercase show_compiler env aliases are honored."""
        with patch.dict(os.environ, {"r2b_show_compiler": "1"}, clear=True):
            config = load_config()

            assert config.ui.show_compiler is True

    def test_load_config_env_can_disable_show_compiler(self, tmp_path):
        """Test false-like environment values override config files."""
        config_path = tmp_path / "show_compiler.toml"
        config_path.write_text("""
[ui]
show_compiler = true
""")

        with patch.dict(os.environ, {"R2B_SHOW_COMPILER": "0"}, clear=True):
            config = load_config(config_path)

            assert config.ui.show_compiler is False

    def test_load_config_without_custom_config(self):
        """Test load_config works without custom config file."""
        # When R2B_CONFIG env var is not set and no config_path provided,
        # load_config should still return a valid AppConfig from defaults
        with patch.dict(os.environ, {"R2B_CONFIG": ""}, clear=False):
            config = load_config()

            assert isinstance(config, AppConfig)

    def test_load_config_picks_up_implicit_local_overlay(self, tmp_path, monkeypatch):
        """config/local.toml should merge without setting R2B_CONFIG."""
        local = tmp_path / "local.toml"
        local.write_text("""
[llm]
provider = "glm"
model = "glm-4.6"
api_key_env = "GLM_API_KEY"
""")
        monkeypatch.setattr("r2b.config.LOCAL_CONFIG_PATH", local)
        monkeypatch.setattr("r2b.config.USER_CONFIG_PATH", tmp_path / "missing.toml")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.delenv("R2B_IGNORE_LOCAL", raising=False)
        monkeypatch.delenv("R2B_CONFIG", raising=False)
        monkeypatch.delenv("R2B_LLM_PROVIDER", raising=False)

        config = load_config()

        assert config.llm.provider == "glm"
        assert config.llm.model == "glm-4.6"
        assert config.llm.api_key_env == "GLM_API_KEY"

    def test_load_config_glm_provider_fills_defaults(self, tmp_path):
        """R2B_LLM_PROVIDER=glm should pick the current GLM model and host."""
        config_path = tmp_path / "empty.toml"
        config_path.write_text("")

        with patch.dict(
            os.environ,
            {
                "R2B_LLM_PROVIDER": "glm",
                "GLM_API_KEY": "glm-secret",
                "R2B_CONFIG": str(config_path),
            },
            clear=False,
        ):
            os.environ.pop("ZAI_API_KEY", None)
            os.environ.pop("R2B_LLM_BASE_URL", None)
            config = load_config(config_path)

        assert config.llm.provider == "glm"
        assert config.llm.model == "glm-5.1"
        assert config.llm.api_key_env == "GLM_API_KEY"
        assert config.llm.base_url == "https://open.bigmodel.cn/api/paas/v4"


class TestLabToolPath:
    def test_apply_lab_tool_path_appends_r2b_tool_path(self, tmp_path, monkeypatch):
        tool_dir = tmp_path / "rebin"
        tool_dir.mkdir()
        monkeypatch.setenv("R2B_TOOL_PATH", str(tool_dir))
        monkeypatch.setenv("PATH", "/usr/bin")
        applied = apply_lab_tool_path()
        assert tool_dir in applied
        parts = os.environ["PATH"].split(":")
        assert parts[0] == "/usr/bin"
        assert str(tool_dir) in parts

    def test_apply_lab_tool_path_ignores_unrelated_home_dirs(self, monkeypatch):
        monkeypatch.delenv("R2B_TOOL_PATH", raising=False)
        monkeypatch.setenv("PATH", "/usr/bin")
        applied = apply_lab_tool_path()
        assert applied == []
        assert os.environ["PATH"] == "/usr/bin"


def test_shipped_config_dir_has_defaults_and_flavors() -> None:
    root = find_checkout_root()
    assert root is not None
    cfg = shipped_config_dir()
    assert cfg == root / "config"
    assert DEFAULT_CONFIG_PATH.is_file()
    assert (cfg / "flavors" / "core.toml").is_file()


class TestDetectEnvironmentHeadless:
    def test_missing_ghidra_is_a_note_not_a_blocker(self):
        from r2b.environment.detectors import detect_environment

        config = AppConfig()
        config.analysis.enable_angr = False
        config.ghidra.install_dir = None
        with (
            patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": ""}, clear=False),
            patch("r2b.environment.ghidra.shutil.which", return_value=None),
        ):
            os.environ.pop("GHIDRA_INSTALL_DIR", None)
            report = detect_environment(config)

        assert report.ghidra is not None
        assert report.ghidra.is_ready is False
        assert not any("GHIDRA_INSTALL_DIR" in issue for issue in report.issues)
        assert any("Ghidra skipped" in note for note in report.notes)
        assert report.llm is not None
        assert report.llm.provider == config.llm.provider

    def test_missing_default_ollama_is_optional(self):
        from r2b.environment import detectors

        config = AppConfig()
        config.analysis.enable_angr = False
        with patch.dict(
            detectors._COMMANDS,
            {"ollama": ["r2b-test-definitely-missing-ollama"]},
        ):
            report = detectors.detect_environment(config)

        assert not any("Missing dependency: ollama" in issue for issue in report.issues)
        assert any("Optional Ollama host missing" in note for note in report.notes)

    def test_enabled_extraction_reports_missing_isolation(self):
        from r2b.environment import detectors

        config = AppConfig()
        config.extract.enable = True
        config.extract.allow_unsafe_fallback = False
        original = detectors._COMMANDS["bwrap"]
        with patch.dict(
            detectors._COMMANDS,
            {"bwrap": ["r2b-test-definitely-missing-bwrap"]},
        ):
            report = detectors.detect_environment(config)
        detectors._COMMANDS["bwrap"] = original

        assert any("fail closed" in note for note in report.notes)


class TestExplicitConfigPath:
    """An explicitly requested config must exist — no silent fallback."""

    def test_missing_explicit_config_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="no-such-file.toml"):
            load_config(tmp_path / "no-such-file.toml")

    def test_existing_explicit_config_loads(self, tmp_path):
        overlay = tmp_path / "overlay.toml"
        overlay.write_text("[llm]\nprovider = 'openai'\nmodel = 'qwen-test'\n")
        config = load_config(overlay)
        assert config.llm.provider == "openai"
        assert config.llm.model == "qwen-test"
