"""Resolve provider-specific LLM keys and endpoints without conflating hosts."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from .providers import canonical_provider, provider_spec

if TYPE_CHECKING:
    from ..config import AppConfig

ZAI_BASE_URL = "https://api.z.ai/api/paas/v4"
BIGMODEL_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"
KIMI_BASE_URL = "https://api.moonshot.ai/v1"
XAI_BASE_URL = "https://api.x.ai/v1"
DEFAULT_GLM_MODEL = "glm-5.1"
DEFAULT_KIMI_MODEL = "kimi-k3"

REMOTE_KEY_HOSTS = (
    "api.openai.com",
    "api.moonshot.ai",
    "api.z.ai",
    "api.x.ai",
    "open.bigmodel.cn",
    "openrouter.ai",
)

CLOUD_KEY_ENVS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "MOONSHOT_API_KEY",
    "KIMI_API_KEY",
    "ZAI_API_KEY",
    "GLM_API_KEY",
    "ZHIPUAI_API_KEY",
    "ZHIPU_API_KEY",
    "OPENROUTER_API_KEY",
)
ZAI_KEY_ENVS = frozenset({"ZAI_API_KEY"})
BIGMODEL_KEY_ENVS = frozenset({"GLM_API_KEY", "ZHIPUAI_API_KEY", "ZHIPU_API_KEY"})
_LOCAL_DEFAULT_MODELS = frozenset(
    {"", "auto", "gemma3:4b", "gemma4:latest", "gemma3:12b", "gemma2:9b"}
)
_OLLAMA_DEFAULT_URL = "http://127.0.0.1:11434"


def is_openai_sdk_provider(provider: str | None) -> bool:
    """Whether the provider uses an OpenAI SDK transport in this process."""
    return canonical_provider(provider) in {
        "openai", "xai", "kimi", "glm", "exo", "openrouter", "vllm", "llamacpp"
    }


def is_glm_family(provider: str | None) -> bool:
    return canonical_provider(provider) == "glm"


def resolve_llm_api_key(
    config: AppConfig,
    provider: str | None = None,
) -> tuple[str | None, str | None]:
    """Return the key for exactly one provider, never an unrelated cloud key."""
    identity = canonical_provider(provider or config.llm.provider)
    names: list[str] = []
    if identity == canonical_provider(config.llm.provider) and config.llm.api_key_env:
        names.append(config.llm.api_key_env)
    if identity == canonical_provider(config.llm.fallback_provider):
        if config.llm.fallback_api_key_env:
            names.append(config.llm.fallback_api_key_env)
    names.extend(provider_spec(identity).api_key_envs)

    seen: set[str] = set()
    for name in names:
        if not name or name in seen:
            continue
        seen.add(name)
        value = os.getenv(name)
        if value:
            return value, name
    return None, names[0] if names else None


def requires_api_key(base_url: str | None) -> bool:
    if not base_url:
        return True
    lowered = base_url.lower()
    return any(host in lowered for host in REMOTE_KEY_HOSTS)


def resolve_provider_base_url(
    config: AppConfig,
    key_env: str | None = None,
    provider: str | None = None,
) -> str | None:
    """Resolve the selected provider's endpoint without conflating host and protocol."""
    identity = canonical_provider(provider or config.llm.provider)
    explicit = (config.llm.base_url or "").rstrip("/")
    has_explicit_provider_url = bool(explicit and explicit != _OLLAMA_DEFAULT_URL)

    if identity == "openai":
        return explicit if has_explicit_provider_url else None
    if identity == "glm":
        if has_explicit_provider_url:
            return explicit
        env_name = key_env
        if env_name is None:
            _, env_name = resolve_llm_api_key(config, identity)
        if env_name in BIGMODEL_KEY_ENVS:
            return BIGMODEL_BASE_URL
        return ZAI_BASE_URL
    if identity == "ollama":
        return explicit or _OLLAMA_DEFAULT_URL
    if has_explicit_provider_url:
        return explicit
    return provider_spec(identity).default_base_url


def apply_provider_defaults(config: AppConfig) -> None:
    """Fill identity-specific model, key name, endpoint, and transport defaults."""
    identity = canonical_provider(config.llm.provider)
    spec = provider_spec(identity)
    config.llm.provider = identity
    if (config.llm.model or "") in _LOCAL_DEFAULT_MODELS and identity != "ollama":
        config.llm.model = spec.default_model
    if not config.llm.api_key_env or config.llm.api_key_env == "ANTHROPIC_API_KEY":
        if spec.api_key_envs:
            config.llm.api_key_env = next(
                (name for name in spec.api_key_envs if os.getenv(name)), spec.api_key_envs[0]
            )
    if identity != "ollama" and config.llm.base_url.rstrip("/") == _OLLAMA_DEFAULT_URL:
        config.llm.base_url = resolve_provider_base_url(config, provider=identity) or ""


def unused_glm_key_hint(config: AppConfig) -> str | None:
    if canonical_provider(config.llm.provider) == "glm":
        return None
    if not any(os.getenv(name) for name in (*BIGMODEL_KEY_ENVS, *ZAI_KEY_ENVS)):
        return None
    present = next(name for name in (*BIGMODEL_KEY_ENVS, *ZAI_KEY_ENVS) if os.getenv(name))
    return (
        f"{present} is set but llm.provider={config.llm.provider!r}. "
        "export R2B_LLM_PROVIDER=glm (or copy config/glm.example.toml to config/local.toml)."
    )


__all__ = [
    "BIGMODEL_BASE_URL",
    "CLOUD_KEY_ENVS",
    "DEFAULT_GLM_MODEL",
    "DEFAULT_KIMI_MODEL",
    "KIMI_BASE_URL",
    "XAI_BASE_URL",
    "ZAI_BASE_URL",
    "apply_provider_defaults",
    "is_glm_family",
    "is_openai_sdk_provider",
    "requires_api_key",
    "resolve_llm_api_key",
    "resolve_provider_base_url",
    "unused_glm_key_hint",
]
