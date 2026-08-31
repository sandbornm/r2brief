"""Anthropic Claude client wrapper."""

from __future__ import annotations

import logging
import os
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


class ChatMessage(BaseModel):
    role: str
    content: str

try:  # pragma: no cover - optional dependency
    from anthropic import Anthropic, APIError, AuthenticationError, RateLimitError
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    Anthropic = None  # type: ignore[misc,assignment]
    APIError = Exception  # type: ignore
    AuthenticationError = Exception  # type: ignore
    RateLimitError = Exception  # type: ignore

_LOGGER = logging.getLogger(__name__)


class ClaudeChatResponse(BaseModel):
    content: str


class ClaudeError(Exception):
    """Wrapper for Anthropic API errors with clean messages."""
    pass


class ClaudeClient:
    """Thin wrapper over Anthropic's Messages API for chat parity with OpenAI client."""

    def __init__(
        self,
        config: AppConfig,
        *,
        provider: str | None = None,
        model: str | None = None,
    ) -> None:
        if Anthropic is None:
            raise ClaudeError(
                "Anthropic package is not installed. Run: uv sync --extra llm"
            )

        api_env = config.llm.api_key_env or "ANTHROPIC_API_KEY"
        api_key = os.getenv(api_env)
        if not api_key:
            raise ClaudeError(
                f"Anthropic API key not found. Set the {api_env} environment variable."
            )

        self._client = Anthropic(api_key=api_key)
        self._config = config
        self._provider = "anthropic"
        # Support both primary and fallback model configuration
        # Default to Opus 4.5 if no model specified
        if config.llm.provider and config.llm.provider.lower() in {"anthropic", "claude"}:
            self._model = model or config.llm.model or "claude-sonnet-5"
        else:
            self._model = model or config.llm.fallback_model or "claude-sonnet-5"

    def generate(
        self,
        messages: Iterable[ChatMessage] | Iterable[dict[str, Any]],
        *,
        tools: Sequence[FunctionTool] = (),
        previous_response: LLMResponse | None = None,
        tool_results: Sequence[ToolResult] = (),
        **_: Any,
    ) -> LLMResponse:
        """Send a conversation through Anthropic Messages and normalize it."""
        del previous_response, tool_results  # history is carried in ``messages``

        system_prompt: str | None = None
        formatted: list[dict[str, Any]] = []

        for message in messages:
            data: dict[str, Any] = (
                message.model_dump() if isinstance(message, ChatMessage) else dict(message)
            )
            role = str(data["role"])
            content = data.get("content", "")

            # Claude handles system prompt separately
            if role == "system":
                if system_prompt is None:
                    system_prompt = content
                else:
                    system_prompt += "\n\n" + content
                continue

            if role == "assistant" and data.get("tool_calls"):
                blocks: list[dict[str, Any]] = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for call in data["tool_calls"]:
                    function = call.get("function", {})
                    arguments = function.get("arguments", {})
                    if isinstance(arguments, str):
                        import json

                        try:
                            arguments = json.loads(arguments)
                        except ValueError:
                            arguments = {"_raw": arguments}
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": call.get("id", ""),
                            "name": function.get("name", ""),
                            "input": arguments,
                        }
                    )
                formatted.append({"role": "assistant", "content": blocks})
            elif role == "tool":
                formatted.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": data.get("tool_call_id", ""),
                                "content": str(content),
                                "is_error": bool(data.get("is_error", False)),
                            }
                        ],
                    }
                )
            else:
                formatted.append({"role": role, "content": content})

        started = perf_counter()
        try:
            params: dict[str, Any] = {
                "model": self._model,
                "max_tokens": self._config.llm.max_tokens,
                "system": system_prompt or "",
                "messages": formatted,
            }
            # Claude 5 accepts only its default sampling configuration.
            claude_5_prefixes = ("claude-sonnet-5", "claude-opus-5", "claude-fable-5")
            if not self._model.lower().startswith(claude_5_prefixes):
                params["temperature"] = self._config.llm.temperature
            if tools:
                params["tools"] = [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": dict(tool.parameters),
                    }
                    for tool in tools
                ]
            response = self._client.messages.create(
                **params,
            )

            segments: list[str] = []
            calls: list[ToolCall] = []
            for part in response.content or ():
                text = getattr(part, "text", None)
                if text:
                    segments.append(text)
                if getattr(part, "type", None) == "tool_use":
                    value = getattr(part, "input", {})
                    calls.append(
                        ToolCall(
                            id=str(getattr(part, "id", "")),
                            name=str(getattr(part, "name", "")),
                            arguments=value if isinstance(value, dict) else {"_value": value},
                        )
                    )
            usage = getattr(response, "usage", None)
            input_tokens = getattr(usage, "input_tokens", None)
            output_tokens = getattr(usage, "output_tokens", None)
            total = (
                input_tokens + output_tokens
                if input_tokens is not None and output_tokens is not None
                else None
            )
            return LLMResponse(
                text="\n".join(segments),
                provider=self._provider,
                model=str(getattr(response, "model", None) or self._model),
                transport=LLMTransport.MESSAGES,
                response_id=getattr(response, "id", None),
                usage=LLMUsage(input_tokens, output_tokens, total),
                finish_reason=getattr(response, "stop_reason", None),
                latency_ms=(perf_counter() - started) * 1000,
                tool_calls=tuple(calls),
            )

        except AuthenticationError:
            raise ClaudeError("Invalid Anthropic API key. Check your ANTHROPIC_API_KEY.")
        except RateLimitError:
            raise ClaudeError("Anthropic rate limit exceeded. Please wait and try again.")
        except APIError as e:
            msg = str(e)
            if hasattr(e, 'message'):
                msg = e.message
            _LOGGER.debug("Anthropic API error: %s", e)
            raise ClaudeError(f"Anthropic API error: {msg}")

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


__all__ = ["ChatMessage", "ClaudeClient", "ClaudeError"]
