from types import SimpleNamespace

import pytest

from r2b.config import AppConfig, LLMSettings
from r2b.llm import FunctionTool, LLMResponse, LLMTransport, ToolCall
from r2b.llm import claude_client as claude_module
from r2b.llm.claude_client import ClaudeClient
from r2b.llm.credentials import apply_provider_defaults, resolve_provider_base_url
from r2b.llm.manager import LLMBridge, LLMError
from r2b.llm.openai_client import OpenAIClient
from r2b.llm.providers import canonical_provider, provider_spec


def test_provider_identities_choose_native_transports():
    assert provider_spec("openai").transport is LLMTransport.RESPONSES
    assert provider_spec("anthropic").transport is LLMTransport.MESSAGES
    assert provider_spec("xai").transport is LLMTransport.RESPONSES
    assert provider_spec("kimi").transport is LLMTransport.CHAT_COMPLETIONS
    assert provider_spec("glm").transport is LLMTransport.CHAT_COMPLETIONS
    assert provider_spec("ollama").transport is LLMTransport.OLLAMA_NATIVE
    assert provider_spec("exo").transport is LLMTransport.RESPONSES
    assert canonical_provider("moonshot") == "kimi"
    assert canonical_provider("grok") == "xai"


def test_kimi_defaults_are_explicit(monkeypatch):
    monkeypatch.setenv("MOONSHOT_API_KEY", "moonshot-secret")
    config = AppConfig(llm=LLMSettings(provider="kimi", model="gemma3:4b"))
    apply_provider_defaults(config)
    assert config.llm.provider == "kimi"
    assert config.llm.model == "kimi-k3"
    assert config.llm.api_key_env == "MOONSHOT_API_KEY"
    assert resolve_provider_base_url(config, provider="kimi") == "https://api.moonshot.ai/v1"


def test_claude_5_uses_default_sampling(monkeypatch):
    calls = []

    class Messages:
        def create(self, **params):
            calls.append(params)
            return SimpleNamespace(
                content=[],
                id="msg-1",
                model="claude-sonnet-5",
                stop_reason="end_turn",
                usage=SimpleNamespace(input_tokens=2, output_tokens=1),
            )

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        claude_module,
        "Anthropic",
        lambda **_: SimpleNamespace(messages=Messages()),
    )
    config = AppConfig(
        llm=LLMSettings(
            provider="anthropic",
            model="claude-sonnet-5",
            api_key_env="ANTHROPIC_API_KEY",
        )
    )
    client = ClaudeClient(config)
    client.generate([{"role": "user", "content": "summarize"}])
    assert "temperature" not in calls[0]


class _Responses:
    def __init__(self):
        self.calls = []

    def create(self, **params):
        self.calls.append(params)
        function_call = SimpleNamespace(
            type="function_call",
            call_id="call-1",
            id="item-1",
            name="inspect_function",
            arguments='{"address":"0x401000"}',
        )
        return SimpleNamespace(
            id="resp-1",
            model="gpt-5.6-luna",
            output_text="",
            output=[function_call],
            usage=SimpleNamespace(input_tokens=10, output_tokens=4, total_tokens=14),
            status="completed",
            incomplete_details=None,
        )


def test_openai_responses_normalizes_tools_and_usage(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    config = AppConfig(
        llm=LLMSettings(
            provider="openai",
            model="gpt-5.6-luna",
            transport="responses",
            api_key_env="OPENAI_API_KEY",
        )
    )
    client = OpenAIClient(config)
    responses = _Responses()
    client._client = SimpleNamespace(responses=responses)
    result = client.generate(
        [{"role": "user", "content": "inspect entry"}],
        tools=(
            FunctionTool(
                "inspect_function",
                "Return deterministic function evidence",
                {
                    "type": "object",
                    "properties": {"address": {"type": "string"}},
                    "required": ["address"],
                },
            ),
        ),
    )
    assert result.provider == "openai"
    assert result.transport is LLMTransport.RESPONSES
    assert result.response_id == "resp-1"
    assert result.usage.total_tokens == 14
    assert result.tool_calls[0].arguments == {"address": "0x401000"}
    assert responses.calls[0]["tools"][0]["name"] == "inspect_function"
    assert "temperature" not in responses.calls[0]


class _SequenceClient:
    def __init__(self):
        self.calls = []

    def generate(self, messages, **kwargs):
        self.calls.append((list(messages), kwargs))
        if len(self.calls) == 1:
            return LLMResponse(
                text="",
                provider="openai",
                model="gpt-5.6-luna",
                transport=LLMTransport.RESPONSES,
                response_id="resp-tool",
                tool_calls=(ToolCall("call-1", "inspect_function", {"address": "0x401000"}),),
            )
        return LLMResponse(
            text="entry is a thunk",
            provider="openai",
            model="gpt-5.6-luna",
            transport=LLMTransport.RESPONSES,
            response_id="resp-final",
            finish_reason="completed",
        )


def _bridge_with_stub():
    config = AppConfig(llm=LLMSettings(provider="openai", max_tool_rounds=2))
    bridge = LLMBridge(config)
    stub = _SequenceClient()
    bridge._get_client = lambda provider: stub
    return bridge, stub


def test_tool_loop_requires_allowlist():
    bridge, _ = _bridge_with_stub()
    tool = FunctionTool("inspect_function", "Inspect", {"type": "object", "properties": {}})
    with pytest.raises(LLMError, match="allowlist"):
        bridge.generate(
            [{"role": "user", "content": "inspect"}],
            tools=(tool,),
            tool_executor=lambda call: {},
        )


def test_tool_calls_are_returned_without_an_executor():
    bridge, stub = _bridge_with_stub()
    tool = FunctionTool("inspect_function", "Inspect", {"type": "object", "properties": {}})
    response = bridge.generate([{"role": "user", "content": "inspect"}], tools=(tool,))
    assert response.tool_calls[0].name == "inspect_function"
    assert len(stub.calls) == 1


def test_tool_loop_is_host_executed_and_bounded():
    bridge, stub = _bridge_with_stub()
    tool = FunctionTool("inspect_function", "Inspect", {"type": "object", "properties": {}})
    executed = []

    def execute(call):
        executed.append(call)
        return {"address": call.arguments["address"], "mnemonics": ["b", "ret"]}

    response = bridge.generate(
        [{"role": "user", "content": "inspect"}],
        tools=(tool,),
        tool_executor=execute,
        allowed_tools={"inspect_function"},
        max_tool_rounds=1,
    )
    assert response.text == "entry is a thunk"
    assert response.tool_rounds == 1
    assert len(executed) == 1
    assert stub.calls[1][1]["previous_response"].response_id == "resp-tool"
    assert stub.calls[1][1]["tool_results"][0].name == "inspect_function"
