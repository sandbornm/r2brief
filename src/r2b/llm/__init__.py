"""LLM clients with provider fallback support."""

from .claude_client import ClaudeClient, ClaudeError
from .manager import LLMBridge, LLMError, ChatMessage
from .ollama_client import OllamaClient, OllamaError
from .openai_client import OpenAIClient, OpenAIError
from .citations import format_cite, parse_cited_claims, proposed_annotations_from_claims
from .prompts import ANALYST_SYSTEM, PROMPT_ID
from .contracts import (
    FunctionTool,
    LLMResponse,
    LLMTransport,
    LLMUsage,
    ProviderCapabilities,
    ToolCall,
    ToolResult,
)
from .providers import PROVIDERS, ProviderSpec, canonical_provider, provider_spec

__all__ = [
    "OpenAIClient",
    "OpenAIError",
    "ClaudeClient",
    "ClaudeError",
    "OllamaClient",
    "OllamaError",
    "ChatMessage",
    "LLMBridge",
    "LLMError",
    "ANALYST_SYSTEM",
    "PROMPT_ID",
    "FunctionTool",
    "LLMResponse",
    "LLMTransport",
    "LLMUsage",
    "ProviderCapabilities",
    "ToolCall",
    "ToolResult",
    "PROVIDERS",
    "ProviderSpec",
    "canonical_provider",
    "provider_spec",
    "format_cite",
    "parse_cited_claims",
    "proposed_annotations_from_claims",
]
