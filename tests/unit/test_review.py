from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, cast

import pytest
from typer.testing import CliRunner

import r2b
from r2b.analysis.review import ReviewError, review_briefing
from r2b.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2b.cli import app
from r2b.llm import LLMResponse, LLMTransport, ToolCall


def _briefing() -> dict[str, Any]:
    digest = "ab" * 32
    return {
        "schema_version": "r2b.briefing.v1",
        "binary": "/evidence/sample",
        "summary": "sample",
        "subject": {"format": "elf", "arch": "arm64/64"},
        "regions": [
            {
                "id": "imports:plt",
                "title": "PLT imports",
                "why": "Process and buffer imports need caller checks.",
                "score": 93,
                "tags": ["imports"],
                "snippet": {
                    "source": "radare2",
                    "kind": "inventory",
                    "text": "execl\nstrcpy",
                    "artifact_id": "imports:plt",
                    "xref": "execl",
                },
                "evidence_refs": [
                    {
                        "action": 1,
                        "result_ref": "/quick_scan/radare2",
                        "output_sha256": digest,
                    }
                ],
            },
            {
                "id": "entry:main",
                "title": "Entry / main",
                "why": "Establish the first callees.",
                "score": 89,
                "tags": ["entry"],
                "snippet": {
                    "source": "radare2",
                    "kind": "disasm",
                    "text": "0x1000 bl sym.imp.strcpy",
                    "address": "0x1000",
                    "function": "main",
                },
            },
            {
                "id": "issue:missing-ghidra",
                "title": "Analysis issue",
                "why": "Ghidra was unavailable.",
                "score": 72,
                "tags": ["issue"],
                "snippet": {
                    "source": "r2b",
                    "kind": "inventory",
                    "text": "Ghidra unavailable",
                },
            },
        ],
        "overall_ask": "",
        "next_steps": [],
        "handoff": {"schema_version": "r2b.handoff.v1", "next_argv": []},
    }


def _model_response(order: list[str], *, evidence: str = "region:{region_id}") -> LLMResponse:
    payload = {
        "order": [
            {
                "region_id": region_id,
                "reason": f"Review {region_id} against the stated thesis.",
                "evidence_ids": [evidence.format(region_id=region_id)],
            }
            for region_id in order
        ]
    }
    return LLMResponse(
        text=json.dumps(payload),
        provider="openai",
        model="test-model",
        transport=LLMTransport.RESPONSES,
        response_id="resp_test",
    )


class _Bridge:
    def __init__(self, response: LLMResponse) -> None:
        self.response = response
        self.calls: list[tuple[list[Any], dict[str, Any]]] = []

    def generate(self, messages: Any, **kwargs: Any) -> LLMResponse:
        values = list(messages)
        self.calls.append((values, kwargs))
        return self.response


def test_rules_mode_is_pure_and_makes_no_model_call() -> None:
    source = _briefing()
    before = deepcopy(source)

    class ExplodingBridge:
        def generate(self, *_args: Any, **_kwargs: Any) -> LLMResponse:
            raise AssertionError("rules mode must not call a model")

    result = review_briefing(
        source,
        mode="rules",
        bridge=cast(Any, ExplodingBridge()),
    )

    assert source == before
    assert result["schema_version"] == "r2b.review.v1"
    assert result["mode"] == "rules"
    assert [item["region_id"] for item in result["base_order"]] == [
        "imports:plt",
        "entry:main",
        "issue:missing-ghidra",
    ]
    assert result["model_order"] is None
    assert result["model"] is None


def test_both_mode_keeps_base_order_and_computes_disagreements() -> None:
    bridge = _Bridge(
        _model_response(["entry:main", "imports:plt", "issue:missing-ghidra"])
    )

    result = review_briefing(
        _briefing(),
        mode="compare",
        thesis="Find the first buffer copy reachable from main.",
        bridge=cast(Any, bridge),
    )

    assert result["mode"] == "both"
    assert [item["region_id"] for item in result["base_order"]] == [
        "imports:plt",
        "entry:main",
        "issue:missing-ghidra",
    ]
    assert [item["region_id"] for item in result["model_order"]] == [
        "entry:main",
        "imports:plt",
        "issue:missing-ghidra",
    ]
    assert {item["region_id"] for item in result["disagreements"]} == {
        "imports:plt",
        "entry:main",
    }
    assert result["model"]["tool_rounds"] == 0
    assert len(bridge.calls) == 1
    messages, kwargs = bridge.calls[0]
    assert kwargs == {"tools": (), "max_tool_rounds": 0}
    prompt = json.loads(messages[1].content)
    assert [item["region_id"] for item in prompt["candidates"]] == sorted(
        ["imports:plt", "entry:main", "issue:missing-ghidra"]
    )
    assert all("score" not in item for item in prompt["candidates"])


def test_llm_mode_does_not_compute_rule_disagreements() -> None:
    bridge = _Bridge(
        _model_response(["entry:main", "imports:plt", "issue:missing-ghidra"])
    )

    result = review_briefing(_briefing(), mode="llm", bridge=cast(Any, bridge))

    assert result["model_order"]
    assert result["disagreements"] == []


@pytest.mark.parametrize(
    ("order", "match"),
    [
        (["entry:main", "unknown", "issue:missing-ghidra"], "unknown region id"),
        (["entry:main", "entry:main", "issue:missing-ghidra"], "duplicate region id"),
        (["entry:main", "imports:plt"], "omitted region ids"),
    ],
)
def test_model_order_fails_closed_on_non_permutations(order: list[str], match: str) -> None:
    bridge = _Bridge(_model_response(order))

    with pytest.raises(ReviewError, match=match):
        review_briefing(_briefing(), mode="llm", bridge=cast(Any, bridge))


def test_model_order_fails_closed_on_unknown_evidence() -> None:
    bridge = _Bridge(
        _model_response(
            ["entry:main", "imports:plt", "issue:missing-ghidra"],
            evidence="snippet:made-up",
        )
    )

    with pytest.raises(ReviewError, match="unknown evidence"):
        review_briefing(_briefing(), mode="llm", bridge=cast(Any, bridge))


def test_review_v1_rejects_model_tool_calls() -> None:
    response = _model_response(["entry:main", "imports:plt", "issue:missing-ghidra"])
    response = LLMResponse(
        text=response.text,
        provider=response.provider,
        model=response.model,
        transport=response.transport,
        tool_calls=(ToolCall(id="call_1", name="verify", arguments={}),),
    )

    with pytest.raises(ReviewError, match="does not permit model tool calls"):
        review_briefing(_briefing(), mode="llm", bridge=cast(Any, _Bridge(response)))


def test_public_api_accepts_nested_analysis_payload() -> None:
    result = r2b.review({"briefing": _briefing()}, mode="rules")

    assert result["schema_version"] == "r2b.review.v1"


def test_analysis_report_has_review_helper(tmp_path: Path) -> None:
    internal = AnalysisResult(
        binary=tmp_path / "sample",
        plan=AnalysisPlan(quick=True, deep=False, persist_trajectory=False),
    )
    result = r2b.AnalysisReport(
        result=internal,
        payload={},
        briefing=_briefing(),
    ).review(mode="rules")

    assert result["mode"] == "rules"


def test_cli_rules_review_emits_one_json_object(tmp_path: Path) -> None:
    path = tmp_path / "briefing.json"
    path.write_text(json.dumps(_briefing()), encoding="utf-8")

    output = CliRunner().invoke(app, ["review", str(path), "--mode", "rules", "--json"])

    assert output.exit_code == 0, output.output
    result = json.loads(output.stdout)
    assert result["schema_version"] == "r2b.review.v1"
    assert result["model_order"] is None


def test_review_schema_names_the_public_contract() -> None:
    schema = json.loads(Path("schemas/review.schema.json").read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == "r2b.review.v1"
    assert schema["properties"]["prompt_id"]["const"] == "r2b.review.prompt.v1"
