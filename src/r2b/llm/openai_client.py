"""OpenAI SDK client with explicit provider identity and transport selection."""

from __future__ import annotations

import json
import logging
from time import perf_counter
from typing import Any, Iterable, Sequence

from pydantic import BaseModel

from ..config import AppConfig
from .contracts import (
    FunctionTool,
    LLMResponse,
    LLMTransport,
    LLMUsage,
    ToolCall,
    ToolResult,
)
from .credentials import (
    is_openai_sdk_provider,
    requires_api_key as _requires_api_key,
    resolve_llm_api_key as _resolve_llm_api_key,
    resolve_provider_base_url as _resolve_provider_base_url,
)
from .providers import canonical_provider, resolve_transport

try:  # pragma: no cover - import guard
    from openai import OpenAI, APIError, AuthenticationError, RateLimitError
except ModuleNotFoundError:  # pragma: no cover
    OpenAI = None  # type: ignore
    APIError = Exception  # type: ignore
    AuthenticationError = Exception  # type: ignore
    RateLimitError = Exception  # type: ignore

_LOGGER = logging.getLogger(__name__)
_CHAT_TEMPLATE_STOPS = ("<|endoftext|>", "<|im_start|>", "<|im_end|>")


class ChatMessage(BaseModel):
    role: str
    content: str


class OpenAIError(Exception):
    """Wrapper for OpenAI-SDK transport errors with clean messages."""


def _truncate_template_leak(content: str) -> str:
    for marker in _CHAT_TEMPLATE_STOPS:
        content = content.split(marker)[0]
    return content


def _rate_limit_message(exc: BaseException, *, base_url: str | None = None) -> str:
    text = " ".join(str(exc).split())
    lowered = text.lower()
    if "1113" in text or "insufficient balance" in lowered or "no resource package" in lowered:
        return (
            "Z.ai/GLM 1113: this host has no package for this key. "
            "Check that the configured Z.ai endpoint and model belong to the key's plan; "
            "some plans use the /api/coding/paas endpoint."
        )
    if "z.ai" in (base_url or "") or "bigmodel" in (base_url or ""):
        host = "Z.ai/GLM"
    elif "moonshot" in (base_url or ""):
        host = "Kimi/Moonshot"
    elif "openrouter" in (base_url or ""):
        host = "OpenRouter"
    elif "x.ai" in (base_url or ""):
        host = "xAI"
    else:
        host = "OpenAI"
    detail = text[:240] + ("..." if len(text) > 240 else "")
    return f"{host} HTTP 429. {detail}"


def _message_dict(message: ChatMessage | dict[str, Any]) -> dict[str, Any]:
    return message.model_dump() if isinstance(message, ChatMessage) else dict(message)


def _json_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _arguments(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return {"_raw": value}
        return decoded if isinstance(decoded, dict) else {"_value": decoded}
    return {"_value": value}


def _usage(value: Any) -> LLMUsage:
    if value is None:
        return LLMUsage()
    input_tokens = getattr(value, "input_tokens", None)
    if input_tokens is None:
        input_tokens = getattr(value, "prompt_tokens", None)
    output_tokens = getattr(value, "output_tokens", None)
    if output_tokens is None:
        output_tokens = getattr(value, "completion_tokens", None)
    total_tokens = getattr(value, "total_tokens", None)
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    return LLMUsage(input_tokens, output_tokens, total_tokens)


def _response_tools(tools: Sequence[FunctionTool]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "name": tool.name,
            "description": tool.description,
            "parameters": dict(tool.parameters),
        }
        for tool in tools
    ]


def _chat_tools(tools: Sequence[FunctionTool]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": dict(tool.parameters),
            },
        }
        for tool in tools
    ]


class OpenAIClient:
    """One SDK, explicit provider identity, and an explicit wire transport."""

    def __init__(
        self,
        config: AppConfig,
        *,
        provider: str | None = None,
        model: str | None = None,
    ) -> None:
        if OpenAI is None:
            raise OpenAIError("OpenAI package is not installed. Run: uv sync --extra llm")

        self._config = config
        self._provider = canonical_provider(provider or config.llm.provider)
        if not is_openai_sdk_provider(self._provider):
            raise OpenAIError(f"Provider {self._provider!r} does not use an OpenAI SDK transport")
        api_key, api_env = _resolve_llm_api_key(config, self._provider)
        base_url = _resolve_provider_base_url(config, api_env, self._provider)
        if not api_key:
            if base_url and not _requires_api_key(base_url):
                api_key = "local"
            else:
                raise OpenAIError(
                    f"API key not found. Set {api_env or 'the provider API key environment variable'}. "
                    "Do not put the key in a committed toml."
                )

        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        self._client = OpenAI(**client_kwargs)
        self._base_url = base_url
        self._api_env = api_env
        self._model = model or (
            config.llm.model
            if self._provider == canonical_provider(config.llm.provider)
            else config.llm.fallback_model
        ) or "gpt-5.6-luna"
        self._transport = resolve_transport(self._provider, config.llm.transport)
        # A custom OpenAI-provider endpoint is assumed to be a local gateway
        # unless the user explicitly chooses a transport.
        if (
            self._provider == "openai"
            and self._base_url
            and config.llm.transport in {"", "auto"}
        ):
            self._transport = LLMTransport.CHAT_COMPLETIONS

    def _uses_new_api(self) -> bool:
        return self._model.lower().startswith(("o1", "o3", "o4", "gpt-4", "gpt-5"))

    def _rejects_temperature(self) -> bool:
        return self._model.lower().startswith(("o1", "o3", "o4", "gpt-5"))

    def generate(
        self,
        messages: Iterable[ChatMessage] | Iterable[dict[str, Any]],
        *,
        tools: Sequence[FunctionTool] = (),
        previous_response: LLMResponse | None = None,
        tool_results: Sequence[ToolResult] = (),
        max_tokens: int | None = None,
        temperature: float | None = None,
        extra_body: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> LLMResponse:
        payload = [_message_dict(message) for message in messages]
        started = perf_counter()
        try:
            if self._transport == LLMTransport.RESPONSES:
                result = self._generate_responses(
                    payload,
                    tools=tools,
                    previous_response=previous_response,
                    tool_results=tool_results,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    extra_body=extra_body,
                    timeout=timeout,
                )
            else:
                result = self._generate_chat_completions(
                    payload,
                    tools=tools,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    extra_body=extra_body,
                    timeout=timeout,
                )
            return LLMResponse(
                text=result.text,
                provider=result.provider,
                model=result.model,
                transport=result.transport,
                response_id=result.response_id,
                usage=result.usage,
                finish_reason=result.finish_reason,
                latency_ms=(perf_counter() - started) * 1000,
                tool_calls=result.tool_calls,
                tool_rounds=result.tool_rounds,
            )
        except AuthenticationError as exc:
            raise OpenAIError(f"Invalid API key. Check {self._api_env}.") from exc
        except RateLimitError as exc:
            raise OpenAIError(_rate_limit_message(exc, base_url=self._base_url)) from exc
        except APIError as exc:
            msg = getattr(exc, "message", None) or str(exc)
            _LOGGER.debug("%s API error: %s", self._provider, exc)
            raise OpenAIError(f"{self._provider} API error: {msg}") from exc

    def _generate_responses(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Sequence[FunctionTool],
        previous_response: LLMResponse | None,
        tool_results: Sequence[ToolResult],
        max_tokens: int | None,
        temperature: float | None,
        extra_body: dict[str, Any] | None,
        timeout: float | None,
    ) -> LLMResponse:
        input_items: list[dict[str, Any]] = messages
        params: dict[str, Any] = {"model": self._model}
        if previous_response and previous_response.response_id:
            params["previous_response_id"] = previous_response.response_id
            input_items = [
                {
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": _json_value(item.output),
                }
                for item in tool_results
            ]
        params["input"] = input_items
        params["max_output_tokens"] = self._config.llm.max_tokens if max_tokens is None else max_tokens
        if not self._rejects_temperature():
            params["temperature"] = self._config.llm.temperature if temperature is None else temperature
        if tools:
            params["tools"] = _response_tools(tools)
        if extra_body:
            params["extra_body"] = extra_body
        if timeout is not None:
            params["timeout"] = timeout

        response = self._client.responses.create(**params)
        calls: list[ToolCall] = []
        for item in getattr(response, "output", ()) or ():
            if getattr(item, "type", None) != "function_call":
                continue
            calls.append(
                ToolCall(
                    id=str(getattr(item, "call_id", None) or getattr(item, "id", "")),
                    name=str(getattr(item, "name", "")),
                    arguments=_arguments(getattr(item, "arguments", {})),
                )
            )
        status = getattr(response, "status", None)
        incomplete = getattr(response, "incomplete_details", None)
        finish = getattr(incomplete, "reason", None) if incomplete else status
        return LLMResponse(
            text=_truncate_template_leak(str(getattr(response, "output_text", "") or "")),
            provider=self._provider,
            model=str(getattr(response, "model", None) or self._model),
            transport=LLMTransport.RESPONSES,
            response_id=getattr(response, "id", None),
            usage=_usage(getattr(response, "usage", None)),
            finish_reason=finish,
            tool_calls=tuple(calls),
        )

    def _generate_chat_completions(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Sequence[FunctionTool],
        max_tokens: int | None,
        temperature: float | None,
        extra_body: dict[str, Any] | None,
        timeout: float | None,
    ) -> LLMResponse:
        params: dict[str, Any] = {"model": self._model, "messages": messages}
        if not self._rejects_temperature():
            params["temperature"] = self._config.llm.temperature if temperature is None else temperature
        token_budget = self._config.llm.max_tokens if max_tokens is None else max_tokens
        params["max_completion_tokens" if self._uses_new_api() else "max_tokens"] = token_budget
        if tools:
            params["tools"] = _chat_tools(tools)
        if extra_body is None and self._base_url and "coding/paas" in self._base_url:
            extra_body = {"thinking": {"type": "disabled"}}
        if extra_body:
            params["extra_body"] = extra_body
        if timeout is not None:
            params["timeout"] = timeout

        completion = self._client.chat.completions.create(**params)
        if not completion.choices:
            raise OpenAIError(f"Model {self._model} returned an empty response (no choices).")
        choice = completion.choices[0]
        message = choice.message
        calls: list[ToolCall] = []
        for call in getattr(message, "tool_calls", ()) or ():
            function = getattr(call, "function", None)
            calls.append(
                ToolCall(
                    id=str(getattr(call, "id", "")),
                    name=str(getattr(function, "name", "")),
                    arguments=_arguments(getattr(function, "arguments", {})),
                )
            )
        return LLMResponse(
            text=_truncate_template_leak(str(getattr(message, "content", "") or "")),
            provider=self._provider,
            model=str(getattr(completion, "model", None) or self._model),
            transport=LLMTransport.CHAT_COMPLETIONS,
            response_id=getattr(completion, "id", None),
            usage=_usage(getattr(completion, "usage", None)),
            finish_reason=getattr(choice, "finish_reason", None),
            tool_calls=tuple(calls),
        )

    def chat(
        self,
        messages: Iterable[ChatMessage] | Iterable[dict[str, Any]],
        **kwargs: Any,
    ) -> str:
        """Compatibility wrapper returning only response text."""
        return self.generate(messages, **kwargs).text

    def summarize_analysis(self, summary: dict[str, Any]) -> str:
        return self.chat(
            [
                ChatMessage(role="system", content="You are a binary analysis assistant."),
                ChatMessage(
                    role="user",
                    content="Summarize the following structured analysis for an engineer:\n" + str(summary),
                ),
            ]
        )


_resolve_provider_api_key = _resolve_llm_api_key
_provider_base_url = _resolve_provider_base_url

__all__ = [
    "ChatMessage",
    "OpenAIClient",
    "OpenAIError",
    "_provider_base_url",
    "_requires_api_key",
    "_resolve_provider_api_key",
    "_truncate_template_leak",
]
