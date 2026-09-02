from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, cast

import pytest
from typer.testing import CliRunner

import r2b
from r2b.analysis.review import ReviewError, review_briefing, review_briefing_set
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


class _SequenceBridge:
    def __init__(self, responses: list[LLMResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[list[Any], dict[str, Any]]] = []

    def generate(self, messages: Any, **kwargs: Any) -> LLMResponse:
        values = list(messages)
        self.calls.append((values, kwargs))
        return self.responses.pop(0)


def _width_briefing() -> dict[str, Any]:
    source = deepcopy(_briefing())
    process = source["regions"][0]
    process.update(
        {
            "id": "imports:process",
            "title": "Process launch / child control",
            "tags": ["imports", "process"],
        }
    )
    process["snippet"]["artifact_id"] = "imports:process"
    source["regions"] = [
        process,
        {
            "id": "imports:network",
            "title": "Network ingress / egress",
            "why": "Network boundary.",
            "score": 90,
            "tags": ["imports", "network"],
            "snippet": {"source": "radare2", "kind": "inventory", "text": "accept\nbind"},
        },
        source["regions"][1],
        {
            "id": "imports:runtime",
            "title": "Runtime loading / memory mapping",
            "why": "Runtime boundary.",
            "score": 87,
            "tags": ["imports", "runtime"],
            "snippet": {"source": "radare2", "kind": "inventory", "text": "dlopen"},
        },
        {
            "id": "imports:memory",
            "title": "Memory and path handling",
            "why": "Caller pivot.",
            "score": 84,
            "tags": ["imports", "memory"],
            "snippet": {"source": "radare2", "kind": "inventory", "text": "strcpy"},
        },
        source["regions"][2],
    ]
    return source


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
    noise = {item["region_id"]: item for item in result["noise_assessment"]["regions"]}
    assert noise["imports:plt"]["disposition"] == "needs_confirmation"
    assert noise["imports:plt"]["claim_strength"] == "lead"
    assert noise["entry:main"]["disposition"] == "actionable"
    assert noise["entry:main"]["claim_strength"] == "corroborated"
    assert noise["issue:missing-ghidra"]["claim_strength"] == "inventory"
    assert result["noise_assessment"]["supported_behavior_region_ids"] == []


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
    assert "Absence of supporting evidence is not proof" in messages[0].content


def test_llm_mode_does_not_compute_rule_disagreements() -> None:
    bridge = _Bridge(
        _model_response(["entry:main", "imports:plt", "issue:missing-ghidra"])
    )

    result = review_briefing(_briefing(), mode="llm", bridge=cast(Any, bridge))

    assert result["model_order"]
    assert result["disagreements"] == []


def test_noise_assessment_uses_verifier_results_as_negative_evidence() -> None:
    source = _briefing()
    source["regions"][0]["snippet"]["text"] = "execl\npopen"
    source["verified_imports"] = [
        {"import": "execl", "status": "no-callers", "call_sites": []},
        {
            "import": "popen",
            "status": "all-constant",
            "call_sites": [
                {
                    "function": "status",
                    "address": "0x1000",
                    "argument": "uptime",
                    "constant": True,
                }
            ],
        },
    ]

    result = review_briefing(source, mode="rules")

    row = result["noise_assessment"]["regions"][0]
    assert row["disposition"] == "low_signal"
    assert row["claim_strength"] == "corroborated"
    assert row["verification_evidence"] == ["execl:no-callers", "popen:all-constant"]
    assert "imports:plt" not in result["noise_assessment"]["focus_region_ids"]
    assert "does not prove safety" in row["reason"]


def test_noise_assessment_does_not_downgrade_partial_verifier_coverage() -> None:
    source = _briefing()
    source["verified_imports"] = [
        {"import": "execl", "status": "no-callers", "call_sites": []},
    ]

    result = review_briefing(source, mode="rules")

    row = result["noise_assessment"]["regions"][0]
    assert row["disposition"] == "needs_confirmation"
    assert row["verification_evidence"] == []


def test_noise_assessment_rejects_inconsistent_verifier_status() -> None:
    source = _briefing()
    source["regions"][0]["snippet"]["text"] = "popen"
    source["verified_imports"] = [
        {"import": "popen", "status": "all-constant", "call_sites": []},
    ]

    result = review_briefing(source, mode="rules")

    row = result["noise_assessment"]["regions"][0]
    assert row["disposition"] == "needs_confirmation"
    assert row["verification_evidence"] == []


def test_noise_assessment_promotes_dynamic_verified_caller() -> None:
    source = _briefing()
    source["regions"][0]["snippet"]["text"] = "popen"
    source["verified_imports"] = [
        {
            "import": "popen",
            "status": "dynamic",
            "call_sites": [
                {
                    "function": "handler",
                    "address": "0x1000",
                    "argument": "<dynamic>",
                    "constant": False,
                }
            ],
        },
    ]

    result = review_briefing(source, mode="rules")

    row = result["noise_assessment"]["regions"][0]
    assert row["disposition"] == "actionable"
    assert row["claim_strength"] == "corroborated"
    assert row["verification_evidence"] == ["popen:dynamic"]
    assert result["noise_assessment"]["supported_behavior_region_ids"] == []


def test_noise_assessment_requires_call_and_dataflow_for_static_behavior() -> None:
    source = _briefing()
    source["regions"][1]["tags"].extend(["caller", "dataflow"])

    result = review_briefing(source, mode="rules")

    assert result["noise_assessment"]["supported_behavior_region_ids"] == [
        "entry:main"
    ]


def test_noise_assessment_deprioritizes_unreferenced_string() -> None:
    source = _briefing()
    source["regions"].append(
        {
            "id": "signal:credential",
            "title": "Credential strings",
            "why": "String material in the image.",
            "score": 70,
            "tags": ["string", "credential"],
            "snippet": {
                "source": "firmware",
                "kind": "strings",
                "text": "admin_password=root",
            },
        }
    )

    result = review_briefing(source, mode="rules")

    rows = {
        item["region_id"]: item for item in result["noise_assessment"]["regions"]
    }
    assert rows["signal:credential"]["disposition"] == "low_signal"
    assert rows["signal:credential"]["missing_evidence"] == [
        "caller_or_xref",
        "data_flow",
    ]
    assert "signal:credential" not in result["noise_assessment"]["focus_region_ids"]


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


def test_rules_width_adds_distinct_regions_without_counting_duplicate_evidence() -> None:
    source = _width_briefing()
    before = deepcopy(source)

    result = review_briefing_set(source, mode="rules", width=3, top_k=2)

    assert source == before
    assert result["schema_version"] == "r2b.review-set.v1"
    assert result["independence"] == "fan_out"
    assert result["noise_assessment"]["policy_id"] == "r2b.noise.v1"
    assert [item["new_region_ids"] for item in result["overlay"]["marginal"]] == [
        ["imports:process", "imports:network"],
        ["imports:runtime"],
        ["imports:memory"],
    ]
    assert result["overlay"]["unique_top_regions"] == 4
    assert result["overlay"]["consensus_region_ids"] == [
        "imports:process",
        "imports:network",
    ]
    evidence_ids = result["overlay"]["unique_evidence_ids"]
    assert len(evidence_ids) == len(set(evidence_ids))


def test_llm_width_fans_out_from_identical_candidates() -> None:
    ids = [
        "imports:process",
        "imports:network",
        "entry:main",
        "imports:runtime",
        "imports:memory",
        "issue:missing-ghidra",
    ]
    bridge = _SequenceBridge(
        [
            _model_response(ids),
            _model_response(
                [
                    "imports:runtime",
                    "imports:process",
                    "imports:network",
                    "entry:main",
                    "imports:memory",
                    "issue:missing-ghidra",
                ]
            ),
        ]
    )

    result = review_briefing_set(
        _width_briefing(),
        mode="llm",
        width=2,
        bridge=cast(Any, bridge),
    )

    assert len(bridge.calls) == 2
    prompts = [json.loads(call[0][1].content) for call in bridge.calls]
    assert prompts[0]["candidates"] == prompts[1]["candidates"]
    assert prompts[0]["thesis"] != prompts[1]["thesis"]
    assert result["overlay"]["marginal"][-1]["model_calls"] == 2


def test_rules_width_rejects_custom_thesis() -> None:
    with pytest.raises(ReviewError, match="require mode llm or both"):
        review_briefing_set(
            _width_briefing(),
            mode="rules",
            width=1,
            theses=["Find parser state transitions."],
        )


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
    assert result["noise_assessment"]["method"] == "deterministic_evidence_maturity"


def test_cli_rules_review_renders_evidence_screen(tmp_path: Path) -> None:
    path = tmp_path / "briefing.json"
    path.write_text(json.dumps(_briefing()), encoding="utf-8")

    output = CliRunner().invoke(app, ["review", str(path), "--mode", "rules"])

    assert output.exit_code == 0, output.output
    assert "needs confirmation" in output.stdout
    assert "supported behavior" in output.stdout
    assert "Low-signal does not mean safe" in output.stdout


def test_cli_width_emits_review_set(tmp_path: Path) -> None:
    path = tmp_path / "briefing.json"
    path.write_text(json.dumps(_width_briefing()), encoding="utf-8")

    output = CliRunner().invoke(
        app,
        ["review", str(path), "--mode", "rules", "--width", "3", "--json"],
    )

    assert output.exit_code == 0, output.output
    result = json.loads(output.stdout)
    assert result["schema_version"] == "r2b.review-set.v1"
    assert result["overlay"]["unique_top_regions"] == 4


def test_review_schema_names_the_public_contract() -> None:
    schema = json.loads(Path("schemas/review.schema.json").read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == "r2b.review.v1"
    assert schema["properties"]["prompt_id"]["const"] == "r2b.review.prompt.v1"
    assert schema["properties"]["noise_assessment"]["$ref"] == "#/$defs/noiseAssessment"
    review_set = json.loads(Path("schemas/review-set.schema.json").read_text(encoding="utf-8"))
    assert review_set["properties"]["schema_version"]["const"] == "r2b.review-set.v1"
