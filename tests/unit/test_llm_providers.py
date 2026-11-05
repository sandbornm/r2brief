import inspect
import typing
from types import SimpleNamespace

import pytest
from anthropic._constants import ANTHROPIC_API_VERSION
from anthropic.resources.messages import Messages as AnthropicMessages
from anthropic.types.model import Model as AnthropicModel

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
    assert "temperature" not in (calls[0].get("extra_body") or {})


_SAMPLING_FIELDS = ("temperature", "top_p", "top_k")
_MISSING = object()


def _sent_sampling(params):
    extra = params.get("extra_body") or {}
    sent = {key: params[key] for key in _SAMPLING_FIELDS if key in params}
    sent.update({key: extra[key] for key in _SAMPLING_FIELDS if key in extra})
    return sent


def _claude(monkeypatch, messages_type, *, api_version=None, **llm):
    class _Client:
        def __init__(self, *_args, **_kwargs):
            self.messages = messages_type()

        @property
        def default_headers(self):
            if not api_version:
                return {}
            return {"anthropic-version": api_version}

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(claude_module, "Anthropic", _Client)
    config = AppConfig(
        llm=LLMSettings(
            provider="anthropic",
            api_key_env="ANTHROPIC_API_KEY",
            **llm,
        )
    )
    return ClaudeClient(config)


def _message(model):
    return SimpleNamespace(
        content=[],
        id="msg-opus",
        model=model,
        stop_reason="end_turn",
        usage=SimpleNamespace(input_tokens=3, output_tokens=2),
    )


def test_legacy_sdk_passes_temperature_keyword(monkeypatch):
    calls = []

    class Messages:
        def create(self, *, model, max_tokens, messages, system=None, temperature=None, tools=None):
            calls.append(
                {
                    "model": model,
                    "temperature": temperature,
                    "tools": tools,
                }
            )
            return _message(model)

    client = _claude(
        monkeypatch,
        Messages,
        api_version="2023-06-01",
        model="claude-opus-4-5",
        temperature=0.4,
    )
    result = client.generate([{"role": "user", "content": "summarize"}])
    assert result.model == "claude-opus-4-5"
    assert calls[0]["temperature"] == 0.4
    assert "extra_body" not in calls[0]


def _sdk_model_ids():
    ids = []
    for arg in typing.get_args(AnthropicModel):
        ids.extend(item for item in typing.get_args(arg) if isinstance(item, str))
    return ids


def test_api_2026_10_21_rejects_sampling_fields(monkeypatch):
    """Locked SDK 2.5 sends this version. temperature in the body is a 400."""
    assert ANTHROPIC_API_VERSION == "2026-10-21"
    accepted = set(inspect.signature(AnthropicMessages.create).parameters)
    assert "temperature" not in accepted
    calls = []

    class Messages:
        def create(self, **params):
            unexpected = sorted(set(params) - accepted)
            if unexpected:
                name = unexpected[0]
                raise TypeError(f"Messages.create() got an unexpected keyword argument {name!r}")
            sent = _sent_sampling(params)
            if sent:
                raise RuntimeError(f"API 2026-10-21 rejects sampling fields: {sorted(sent)}")
            calls.append(params)
            return _message(params["model"])

    for model in ("claude-opus-4-5", "claude-haiku-5-5", "claude-mythos-5"):
        calls.clear()
        client = _claude(monkeypatch, Messages, model=model, temperature=0.2)
        result = client.generate([{"role": "user", "content": "summarize"}])
        assert result.model == model
        assert _sent_sampling(calls[0]) == {}


def _is_claude_5_id(model: str) -> bool:
    """Generation 5, not a 4.5 id such as claude-haiku-4-5."""
    _family, _sep, rest = model.removeprefix("claude-").partition("-")
    return rest == "5" or rest.startswith(("5-", "5."))


def test_anthropic_1_uses_extra_body_only_for_pre_claude_5(monkeypatch):
    calls = []

    class Messages:
        def create(self, **params):
            if "temperature" in params:
                raise TypeError("Messages.create() got an unexpected keyword argument 'temperature'")
            calls.append(params)
            return _message(params["model"])

    client = _claude(
        monkeypatch,
        Messages,
        api_version="2023-06-01",
        model="claude-opus-4-5",
        temperature=0.2,
    )
    client.generate([{"role": "user", "content": "summarize"}])
    assert "temperature" not in calls[0]
    assert calls[0]["extra_body"] == {"temperature": 0.2}

    for model in ("claude-haiku-5-5", "claude-mythos-5", "claude-sonnet-5"):
        calls.clear()
        client = _claude(
            monkeypatch,
            Messages,
            api_version="2023-06-01",
            model=model,
            temperature=0.2,
        )
        client.generate([{"role": "user", "content": "summarize"}])
        assert _sent_sampling(calls[0]) == {}, model


def test_sdk_claude_5_ids_omit_sampling(monkeypatch):
    ids = _sdk_model_ids()
    assert "claude-haiku-5-5" in ids
    assert "claude-mythos-5" in ids
    calls = []

    class Messages:
        def create(self, *, model, max_tokens, messages, system=None, temperature=_MISSING, tools=None):
            calls.append({"model": model, "temperature": temperature})
            return _message(model)

    for model in ids:
        calls.clear()
        client = _claude(
            monkeypatch,
            Messages,
            api_version="2023-06-01",
            model=model,
            temperature=0.3,
        )
        client.generate([{"role": "user", "content": "summarize"}])
        if _is_claude_5_id(model):
            assert calls[0]["temperature"] is _MISSING, model
        else:
            assert calls[0]["temperature"] == 0.3, model


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
