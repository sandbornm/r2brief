"""Explicit provider identities, transports, and capability metadata."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import LLMTransport, ProviderCapabilities


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    id: str
    display_name: str
    transport: LLMTransport
    default_model: str
    api_key_envs: tuple[str, ...] = ()
    default_base_url: str | None = None
    capabilities: ProviderCapabilities = ProviderCapabilities()


_RESPONSES_CAPABILITIES = ProviderCapabilities(
    tools=True,
    reasoning=True,
    structured_output=True,
    continuation=True,
    usage=True,
)
_CHAT_CAPABILITIES = ProviderCapabilities(
    tools=True,
    reasoning=False,
    structured_output=True,
    continuation=False,
    usage=True,
)


PROVIDERS: dict[str, ProviderSpec] = {
    "openai": ProviderSpec(
        id="openai",
        display_name="OpenAI",
        transport=LLMTransport.RESPONSES,
        default_model="gpt-5.6-luna",
        api_key_envs=("OPENAI_API_KEY",),
        capabilities=_RESPONSES_CAPABILITIES,
    ),
    "anthropic": ProviderSpec(
        id="anthropic",
        display_name="Anthropic",
        transport=LLMTransport.MESSAGES,
        default_model="claude-sonnet-5",
        api_key_envs=("ANTHROPIC_API_KEY",),
        capabilities=ProviderCapabilities(
            tools=True,
            reasoning=True,
            structured_output=True,
            continuation=False,
            usage=True,
        ),
    ),
    "xai": ProviderSpec(
        id="xai",
        display_name="xAI",
        transport=LLMTransport.RESPONSES,
        default_model="grok-4.6",
        api_key_envs=("XAI_API_KEY",),
        default_base_url="https://api.x.ai/v1",
        capabilities=_RESPONSES_CAPABILITIES,
    ),
    "kimi": ProviderSpec(
        id="kimi",
        display_name="Kimi / Moonshot",
        transport=LLMTransport.CHAT_COMPLETIONS,
        default_model="kimi-k3",
        api_key_envs=("MOONSHOT_API_KEY", "KIMI_API_KEY"),
        default_base_url="https://api.moonshot.ai/v1",
        capabilities=_CHAT_CAPABILITIES,
    ),
    "glm": ProviderSpec(
        id="glm",
        display_name="Z.ai / GLM",
        transport=LLMTransport.CHAT_COMPLETIONS,
        default_model="glm-5.1",
        api_key_envs=("ZAI_API_KEY", "GLM_API_KEY", "ZHIPUAI_API_KEY", "ZHIPU_API_KEY"),
        default_base_url="https://api.z.ai/api/paas/v4",
        capabilities=ProviderCapabilities(
            tools=True,
            reasoning=True,
            structured_output=True,
            continuation=False,
            usage=True,
        ),
    ),
    "ollama": ProviderSpec(
        id="ollama",
        display_name="Ollama",
        transport=LLMTransport.OLLAMA_NATIVE,
        default_model="gemma3:4b",
        default_base_url="http://127.0.0.1:11434",
        capabilities=ProviderCapabilities(
            tools=True,
            reasoning=False,
            structured_output=True,
            continuation=False,
            usage=True,
        ),
    ),
    "exo": ProviderSpec(
        id="exo",
        display_name="exo",
        transport=LLMTransport.RESPONSES,
        default_model="auto",
        default_base_url="http://127.0.0.1:52415/v1",
        capabilities=_RESPONSES_CAPABILITIES,
    ),
    # Explicit identities retained for common user overlays. These are not
    # collapsed into a vague SDK/wire-protocol label.
    "openrouter": ProviderSpec(
        id="openrouter",
        display_name="OpenRouter",
        transport=LLMTransport.CHAT_COMPLETIONS,
        default_model="openai/gpt-5.6-luna",
        api_key_envs=("OPENROUTER_API_KEY",),
        default_base_url="https://openrouter.ai/api/v1",
        capabilities=_CHAT_CAPABILITIES,
    ),
    "vllm": ProviderSpec(
        id="vllm",
        display_name="vLLM",
        transport=LLMTransport.CHAT_COMPLETIONS,
        default_model="auto",
        capabilities=_CHAT_CAPABILITIES,
    ),
    "llamacpp": ProviderSpec(
        id="llamacpp",
        display_name="llama.cpp",
        transport=LLMTransport.CHAT_COMPLETIONS,
        default_model="auto",
        capabilities=_CHAT_CAPABILITIES,
    ),
}

_ALIASES = {
    "claude": "anthropic",
    "grok": "xai",
    "x.ai": "xai",
    "moonshot": "kimi",
    "zai": "glm",
    "z.ai": "glm",
    "zhipu": "glm",
    "bigmodel": "glm",
    "local": "ollama",
    "llama.cpp": "llamacpp",
}


def canonical_provider(provider: str | None) -> str:
    value = (provider or "ollama").strip().lower()
    return _ALIASES.get(value, value)


def provider_spec(provider: str | None) -> ProviderSpec:
    identity = canonical_provider(provider)
    try:
        return PROVIDERS[identity]
    except KeyError as exc:
        supported = ", ".join(PROVIDERS)
        raise ValueError(f"Unknown LLM provider {provider!r}; supported: {supported}") from exc


def resolve_transport(provider: str | None, configured: str | None = None) -> LLMTransport:
    if configured and configured.strip().lower() not in {"", "auto"}:
        try:
            return LLMTransport(configured.strip().lower())
        except ValueError as exc:
            supported = ", ".join(item.value for item in LLMTransport)
            raise ValueError(f"Unknown LLM transport {configured!r}; supported: {supported}") from exc
    return provider_spec(provider).transport


__all__ = [
    "PROVIDERS",
    "ProviderSpec",
    "canonical_provider",
    "provider_spec",
    "resolve_transport",
]
