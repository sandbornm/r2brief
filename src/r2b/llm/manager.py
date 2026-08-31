"""Provider-neutral LLM facade with bounded, host-owned function tools."""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import replace
import json
import logging
from typing import Any

from ..config import AppConfig
from .claude_client import ClaudeClient, ClaudeError
from .contracts import (
    FunctionTool,
    LLMResponse,
    ProviderCapabilities,
    ToolExecutor,
    ToolResult,
)
from .credentials import is_openai_sdk_provider
from .ollama_client import OllamaClient, OllamaError, list_ollama_models, select_ollama_model
from .openai_client import ChatMessage, OpenAIClient, OpenAIError
from .providers import PROVIDERS, canonical_provider, provider_spec

_LOGGER = logging.getLogger(__name__)


class LLMError(Exception):
    """High-level error for LLM operations."""


Client = OpenAIClient | ClaudeClient | OllamaClient
ExecutorMap = Mapping[str, Callable[[Mapping[str, Any]], Any]]


def _portable_tool_messages(response: LLMResponse, results: Sequence[ToolResult]) -> list[dict[str, Any]]:
    assistant_calls = [
        {
            "id": call.id,
            "type": "function",
            "function": {
                "name": call.name,
                "arguments": json.dumps(call.arguments, sort_keys=True, default=str),
            },
        }
        for call in response.tool_calls
    ]
    messages: list[dict[str, Any]] = [
        {"role": "assistant", "content": response.text, "tool_calls": assistant_calls}
    ]
    for result in results:
        output = result.output if isinstance(result.output, str) else json.dumps(
            result.output, sort_keys=True, default=str
        )
        messages.append(
            {
                "role": "tool",
                "tool_call_id": result.call_id,
                "name": result.name,
                "content": output,
                "is_error": result.is_error,
            }
        )
    return messages


class LLMBridge:
    """Select a provider and normalize text, metadata, usage, and tool calls."""

    DEFAULT_MODEL = "gemma3:4b"
    AVAILABLE_MODELS = [
        ("ollama", "gemma4:latest", "Gemma 4 (local)"),
        ("ollama", "gemma3:4b", "Gemma 3 4B (local)"),
        ("openai", "gpt-5.6-luna", "GPT-5.6 Luna"),
        ("anthropic", "claude-sonnet-5", "Claude Sonnet 5"),
        ("xai", "grok-4.6", "Grok 4.6"),
        ("kimi", "kimi-k3", "Kimi K3"),
        ("glm", "glm-5.1", "GLM 5.1"),
    ]

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._order: list[str] = []
        self._clients: dict[str, Client] = {}
        self._errors: dict[str, str] = {}
        self._last_provider: str | None = None
        self._last_response: LLMResponse | None = None

        if config.llm.provider:
            self._order.append(canonical_provider(config.llm.provider))
        if config.llm.enable_fallback and config.llm.fallback_provider:
            fallback = canonical_provider(config.llm.fallback_provider)
            if fallback not in self._order:
                self._order.append(fallback)
        if "ollama" in self._order:
            self._config.llm.model = select_ollama_model(
                self._config.llm.base_url, self._config.llm.model
            )

    def generate(
        self,
        messages: Iterable[ChatMessage] | Iterable[dict[str, Any]],
        *,
        tools: Sequence[FunctionTool] = (),
        tool_executor: ToolExecutor | ExecutorMap | None = None,
        allowed_tools: Collection[str] | None = None,
        max_tool_rounds: int | None = None,
    ) -> LLMResponse:
        """Generate a normalized response and optionally run a bounded tool loop.

        Tool execution requires all three controls: declared ``tools``, an
        explicit executor, and an explicit ``allowed_tools`` collection. With
        no executor, requested tool calls are returned to the host untouched.
        """
        declared = {tool.name: tool for tool in tools}
        if len(declared) != len(tools):
            raise LLMError("Tool names must be unique")
        if tool_executor is not None and allowed_tools is None:
            raise LLMError("Tool execution requires an explicit allowed_tools allowlist")
        allowed = set(allowed_tools or ())
        unknown_allowed = allowed - declared.keys()
        if unknown_allowed:
            raise LLMError(f"Allowlist names undeclared tools: {', '.join(sorted(unknown_allowed))}")
        round_limit = self._config.llm.max_tool_rounds if max_tool_rounds is None else max_tool_rounds
        if not 0 <= round_limit <= 8:
            raise LLMError("max_tool_rounds must be between 0 and 8")

        conversation = [
            message.model_dump() if isinstance(message, ChatMessage) else dict(message)
            for message in messages
        ]
        errors: list[str] = []
        for provider in self._order:
            client = self._get_client(provider)
            if client is None:
                if provider in self._errors:
                    errors.append(f"{provider}: {self._errors[provider]}")
                continue
            if tools and not provider_spec(provider).capabilities.tools:
                errors.append(f"{provider}: configured transport does not support function tools")
                continue

            previous: LLMResponse | None = None
            tool_results: tuple[ToolResult, ...] = ()
            rounds = 0
            while True:
                try:
                    response = client.generate(
                        conversation,
                        tools=tools,
                        previous_response=previous,
                        tool_results=tool_results,
                    )
                except (OpenAIError, ClaudeError, OllamaError) as exc:
                    error_msg = str(exc)
                    self._errors[provider] = error_msg
                    errors.append(f"{provider}: {error_msg}")
                    _LOGGER.warning("LLM provider %s failed: %s", provider, error_msg)
                    # Never replay already-executed tools against a fallback.
                    if rounds:
                        raise LLMError(f"LLM request failed after tool execution. {provider}: {error_msg}") from exc
                    break
                except Exception as exc:
                    error_msg = f"Unexpected error: {type(exc).__name__}"
                    self._errors[provider] = error_msg
                    errors.append(f"{provider}: {error_msg}")
                    _LOGGER.exception("Unexpected LLM error from %s", provider)
                    if rounds:
                        raise LLMError(f"LLM request failed after tool execution. {provider}: {error_msg}") from exc
                    break

                self._last_provider = response.provider
                self._last_response = response
                if not response.tool_calls or tool_executor is None or allowed_tools is None:
                    return replace(response, tool_rounds=rounds)
                if rounds >= round_limit:
                    raise LLMError(
                        f"Model requested tools after the {round_limit}-round execution limit"
                    )

                results: list[ToolResult] = []
                for call in response.tool_calls:
                    if call.name not in declared:
                        raise LLMError(f"Model requested undeclared tool {call.name!r}")
                    if call.name not in allowed:
                        raise LLMError(f"Model requested non-allowlisted tool {call.name!r}")
                    try:
                        if isinstance(tool_executor, Mapping):
                            callback = tool_executor.get(call.name)
                            if callback is None:
                                raise LLMError(f"No executor registered for tool {call.name!r}")
                            output = callback(call.arguments)
                        else:
                            output = tool_executor(call)
                        results.append(ToolResult(call.id, call.name, output))
                    except LLMError:
                        raise
                    except Exception as exc:
                        results.append(
                            ToolResult(
                                call.id,
                                call.name,
                                {"error": f"{type(exc).__name__}: {exc}"},
                                is_error=True,
                            )
                        )
                rounds += 1
                tool_results = tuple(results)
                conversation.extend(_portable_tool_messages(response, tool_results))
                previous = response

        if errors:
            raise LLMError("LLM request failed. " + " | ".join(errors))
        raise LLMError(
            "No LLM providers configured. Start Ollama or configure an explicit hosted provider."
        )

    def chat(self, messages: Iterable[ChatMessage] | Iterable[dict[str, Any]]) -> str:
        """Compatibility wrapper returning only model text."""
        return self.generate(messages).text

    def summarize_analysis(self, summary: dict[str, object]) -> str:
        return self.chat(
            [
                ChatMessage(role="system", content="You are a senior binary analysis assistant."),
                ChatMessage(
                    role="user",
                    content="Summarize this structured evidence for an engineer:\n" + str(summary),
                ),
            ]
        )

    def _get_client(self, provider: str) -> Client | None:
        identity = canonical_provider(provider)
        if identity in self._clients:
            return self._clients[identity]
        try:
            if is_openai_sdk_provider(identity):
                client: Client = OpenAIClient(self._config, provider=identity)
            elif identity == "anthropic":
                client = ClaudeClient(self._config, provider=identity)
            elif identity == "ollama":
                client = OllamaClient(self._config)
            else:
                self._errors[identity] = f"Unknown provider: {provider}"
                return None
        except (OpenAIError, ClaudeError, OllamaError, ValueError) as exc:
            self._errors[identity] = str(exc)
            _LOGGER.debug("Failed to initialize %s client: %s", identity, exc)
            return None
        except Exception as exc:
            self._errors[identity] = f"Initialization failed: {type(exc).__name__}"
            _LOGGER.exception("Failed to initialize %s client", identity)
            return None
        self._clients[identity] = client
        return client

    def set_model(self, model: str) -> None:
        model_info = self._model_info(model)
        if not model_info:
            raise LLMError(f"Unknown model: {model}. Available: {', '.join(self.available_models)}")
        provider, model_id, _ = model_info
        self._config.llm.model = model_id
        self._config.llm.provider = provider
        self._order = [provider]
        if self._config.llm.enable_fallback and self._config.llm.fallback_provider:
            fallback = canonical_provider(self._config.llm.fallback_provider)
            if fallback != provider:
                self._order.append(fallback)
        self._clients.clear()

    @property
    def model(self) -> str:
        return self._config.llm.model

    @property
    def available_models(self) -> list[str]:
        installed = list_ollama_models(self._config.llm.base_url)
        local = installed or [model for provider, model, _ in self.AVAILABLE_MODELS if provider == "ollama"]
        remote = [model for provider, model, _ in self.AVAILABLE_MODELS if provider != "ollama"]
        models = [*local, *remote]
        if self._config.llm.model not in models:
            models.insert(0, self._config.llm.model)
        return list(dict.fromkeys(models))

    @property
    def model_display_names(self) -> dict[str, str]:
        names = {model: display for _, model, display in self.AVAILABLE_MODELS}
        for model in list_ollama_models(self._config.llm.base_url):
            names.setdefault(model, f"{model} (local)")
        return names

    @property
    def errors(self) -> dict[str, str]:
        return self._errors.copy()

    @property
    def providers(self) -> list[str]:
        return list(self._order)

    @property
    def last_provider(self) -> str | None:
        return self._last_provider

    @property
    def last_response(self) -> LLMResponse | None:
        return self._last_response

    @property
    def capabilities(self) -> ProviderCapabilities:
        """Capability metadata for the configured primary provider."""
        return provider_spec(self._order[0] if self._order else None).capabilities

    def is_available(self) -> bool:
        return any(self._get_client(provider) is not None for provider in self._order)

    def _model_info(self, model: str) -> tuple[str, str, str] | None:
        static = next((entry for entry in self.AVAILABLE_MODELS if entry[1] == model), None)
        if static:
            return static
        if model in list_ollama_models(self._config.llm.base_url):
            return ("ollama", model, f"{model} (local)")
        # A custom model remains valid for the currently selected explicit provider.
        if model == self._config.llm.model and canonical_provider(self._config.llm.provider) in PROVIDERS:
            return (canonical_provider(self._config.llm.provider), model, model)
        return None


__all__ = ["LLMBridge", "LLMError", "ChatMessage"]
