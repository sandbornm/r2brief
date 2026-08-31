"""Ollama chat client for local models such as Gemma."""

from __future__ import annotations

from time import perf_counter
from typing import Any, Iterable, Sequence

import httpx
from pydantic import BaseModel

from ..config import AppConfig
from .contracts import FunctionTool, LLMResponse, LLMTransport, LLMUsage, ToolCall, ToolResult


class ChatMessage(BaseModel):
    role: str
    content: str


class OllamaError(Exception):
    """Wrapper for local Ollama API errors."""


class OllamaClient:
    """Small HTTP client for Ollama's local chat API."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._base_url = config.llm.base_url.rstrip("/")
        self._model = select_ollama_model(self._base_url, config.llm.model)
        self._config.llm.model = self._model
        self._timeout = httpx.Timeout(connect=2.0, read=180.0, write=20.0, pool=5.0)

    def generate(
        self,
        messages: Iterable[ChatMessage] | Iterable[dict[str, Any]],
        *,
        tools: Sequence[FunctionTool] = (),
        previous_response: LLMResponse | None = None,
        tool_results: Sequence[ToolResult] = (),
        **_: Any,
    ) -> LLMResponse:
        del previous_response, tool_results  # history is carried in ``messages``
        payload_messages: list[dict[str, Any]] = []
        for message in messages:
            if isinstance(message, ChatMessage):
                payload_messages.append(message.model_dump())
            else:
                payload_messages.append(dict(message))

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": payload_messages,
            "stream": False,
            "options": {
                "temperature": self._config.llm.temperature,
                "num_predict": self._config.llm.max_tokens,
            },
        }
        if tools:
            payload["tools"] = [
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

        started = perf_counter()
        try:
            response = httpx.post(
                f"{self._base_url}/api/chat",
                json=payload,
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise OllamaError(
                f"Ollama is not reachable at {self._base_url}. "
                f"Start Ollama and run: ollama pull {self._model}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise OllamaError(f"Ollama HTTP error: {exc.response.status_code} {exc.response.text[:500]}") from exc
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama request failed: {exc}") from exc

        data = response.json()
        message = data.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            calls: list[ToolCall] = []
            for index, call in enumerate(message.get("tool_calls") or ()):
                if not isinstance(call, dict):
                    continue
                function = call.get("function") or {}
                if not isinstance(function, dict):
                    continue
                arguments = function.get("arguments") or {}
                calls.append(
                    ToolCall(
                        id=str(call.get("id") or f"ollama-{index}"),
                        name=str(function.get("name") or ""),
                        arguments=arguments if isinstance(arguments, dict) else {"_value": arguments},
                    )
                )
            if isinstance(content, str) or calls:
                input_tokens = data.get("prompt_eval_count")
                output_tokens = data.get("eval_count")
                total = (
                    input_tokens + output_tokens
                    if isinstance(input_tokens, int) and isinstance(output_tokens, int)
                    else None
                )
                return LLMResponse(
                    text=content if isinstance(content, str) else "",
                    provider="ollama",
                    model=str(data.get("model") or self._model),
                    transport=LLMTransport.OLLAMA_NATIVE,
                    response_id=None,
                    usage=LLMUsage(
                        input_tokens if isinstance(input_tokens, int) else None,
                        output_tokens if isinstance(output_tokens, int) else None,
                        total,
                    ),
                    finish_reason=data.get("done_reason"),
                    latency_ms=(perf_counter() - started) * 1000,
                    tool_calls=tuple(calls),
                )
        raise OllamaError("Ollama returned an unexpected response shape.")

    def chat(self, messages: Iterable[ChatMessage] | Iterable[dict[str, Any]]) -> str:
        """Compatibility wrapper returning only response text."""
        return self.generate(messages).text

    def summarize_analysis(self, summary: dict[str, Any]) -> str:
        messages = [
            ChatMessage(role="system", content="You are a binary analysis assistant."),
            ChatMessage(
                role="user",
                content="Summarize the following structured analysis for an engineer:\n" + str(summary),
            ),
        ]
        return self.chat(messages)

def list_ollama_models(base_url: str, *, timeout: float = 1.5) -> list[str]:
    """Return installed Ollama model names, or an empty list if unavailable."""
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=timeout)
        response.raise_for_status()
    except httpx.HTTPError:
        return []

    payload = response.json()
    models = payload.get("models")
    if not isinstance(models, list):
        return []

    names: list[str] = []
    for model in models:
        if not isinstance(model, dict):
            continue
        name = model.get("name") or model.get("model")
        if isinstance(name, str) and name:
            names.append(name)
    return sorted(set(names))


def select_ollama_model(base_url: str, preferred: str) -> str:
    """Choose an installed Ollama model, preferring Gemma for local chat."""
    installed = list_ollama_models(base_url)
    if not installed or preferred in installed:
        return preferred

    gemma_models = [model for model in installed if model.lower().startswith("gemma")]
    if gemma_models:
        return sorted(gemma_models, key=_ollama_model_rank)[0]
    return installed[0]


def _ollama_model_rank(model: str) -> tuple[int, str]:
    lower = model.lower()
    if lower.startswith("gemma4"):
        return (0, lower)
    if lower.startswith("gemma3"):
        return (1, lower)
    if lower.startswith("gemma2"):
        return (2, lower)
    return (9, lower)


__all__ = ["ChatMessage", "OllamaClient", "OllamaError", "list_ollama_models", "select_ollama_model"]
