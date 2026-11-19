import re

from r2b.config import AppConfig, LLMSettings
from r2b.llm import claude_client as claude_module
from r2b.llm import openai_client as openai_module
from r2b.llm.claude_client import ClaudeClient
from r2b.llm.manager import LLMBridge
from r2b.llm.openai_client import OpenAIClient
from r2b.llm.providers import PROVIDERS
from r2b.paths import shipped_config_dir

# Retired ids cited from
# https://platform.claude.com/docs/en/about-claude/model-deprecations
# and https://developers.openai.com/api/docs/deprecations
RETIRED_MODEL_IDS = frozenset({
    "claude-sonnet-4-5", "claude-sonnet-4-5-20250929", "claude-sonnet-4-20250514",
    "claude-opus-4-20250514", "claude-opus-4-1", "claude-opus-4-1-20250805",
    "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-haiku-20240307",
    "gpt-4o", "gpt-4.1", "gpt-4.1-mini", "gpt-5", "gpt-5-mini", "gpt-5-nano", "o3",
})
_MODEL_LINE = re.compile(r'^\s*#?\s*model\s*=\s*"([^"]+)"')


def _is_retired(model: str) -> bool:
    # OpenRouter ids add a vendor prefix; Anthropic ones also use dots for dashes.
    bare = model.split("/", 1)[-1]
    return bare in RETIRED_MODEL_IDS or bare.replace(".", "-") in RETIRED_MODEL_IDS


def test_shipped_defaults_are_not_retired(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(claude_module, "Anthropic", lambda **_kwargs: object())
    monkeypatch.setattr(openai_module, "OpenAI", lambda **_kwargs: object())
    claude = ClaudeClient(AppConfig(llm=LLMSettings(provider="anthropic", model="")))
    claude_fb = ClaudeClient(AppConfig(llm=LLMSettings(provider="openai", fallback_model=None)))
    openai = OpenAIClient(AppConfig(llm=LLMSettings(provider="openai", model="")))
    models = [
        LLMSettings().fallback_model,
        *(spec.default_model for spec in PROVIDERS.values()),
        *(model for _, model, _ in LLMBridge.AVAILABLE_MODELS),
        claude._model,
        claude_fb._model,
        openai._model,
    ]
    retired = [model for model in models if model and _is_retired(model)]
    assert retired == []


def test_config_toml_models_are_not_retired() -> None:
    seen: list[str] = []
    retired: list[str] = []
    for path in sorted(shipped_config_dir().glob("*.toml")):
        for line in path.read_text().splitlines():
            if (match := _MODEL_LINE.match(line)) is None:
                continue
            seen.append(match.group(1))
            if _is_retired(match.group(1)):
                retired.append(f"{path.name}: {match.group(1)}")
    assert seen
    assert retired == []
