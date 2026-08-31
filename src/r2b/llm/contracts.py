"""Provider-neutral contracts for model responses and host-owned tools.

The model may *request* a tool.  Only :class:`LLMBridge` may execute one,
and only when the caller supplies both an executor and an explicit allowlist.
This keeps analysis deterministic unless its host deliberately opts into a
bounded model/tool loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping


class LLMTransport(str, Enum):
    """Wire protocols supported by the built-in clients."""

    RESPONSES = "responses"
    MESSAGES = "messages"
    CHAT_COMPLETIONS = "chat_completions"
    OLLAMA_NATIVE = "ollama_native"


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    """Features r2b can normalize for a provider/transport pair."""

    tools: bool = False
    reasoning: bool = False
    structured_output: bool = False
    continuation: bool = False
    usage: bool = True


@dataclass(frozen=True, slots=True)
class LLMUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class FunctionTool:
    """A JSON-schema function exposed to a model, not an executable callback."""

    name: str
    description: str
    parameters: Mapping[str, Any] = field(
        default_factory=lambda: {"type": "object", "properties": {}}
    )

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Invalid tool name: {self.name!r}")
        if self.parameters.get("type") != "object":
            raise ValueError(f"Tool {self.name!r} parameters must be an object schema")


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ToolResult:
    call_id: str
    name: str
    output: Any
    is_error: bool = False


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Normalized response returned by every provider client."""

    text: str
    provider: str
    model: str
    transport: LLMTransport
    response_id: str | None = None
    usage: LLMUsage = field(default_factory=LLMUsage)
    finish_reason: str | None = None
    latency_ms: float | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    tool_rounds: int = 0


ToolExecutor = Callable[[ToolCall], Any]


def tool_map(*tools: FunctionTool) -> dict[str, FunctionTool]:
    """Build a name-indexed tool map and reject ambiguous definitions."""
    mapped = {tool.name: tool for tool in tools}
    if len(mapped) != len(tools):
        raise ValueError("Tool names must be unique")
    return mapped


__all__ = [
    "FunctionTool",
    "LLMResponse",
    "LLMTransport",
    "LLMUsage",
    "ProviderCapabilities",
    "ToolCall",
    "ToolExecutor",
    "ToolResult",
    "tool_map",
]
