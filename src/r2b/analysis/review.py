"""Optional, goal-aware review of a deterministic r2b briefing.

The briefing remains the source of truth.  A model may only reorder the
candidate region IDs and cite evidence capsules already present in that
briefing.  Review output is a separate, versioned document and never mutates
the briefing, its scores, or its handoff.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal, Mapping

from ..config import AppConfig, load_config
from ..llm import ChatMessage, LLMBridge, LLMError, LLMResponse

REVIEW_SCHEMA_VERSION = "r2b.review.v1"
REVIEW_PROMPT_ID = "r2b.review.prompt.v1"
ReviewMode = Literal["rules", "llm", "both", "compare"]

_MODEL_SYSTEM = f"""You review a fixed set of binary-analysis evidence regions.
Return one JSON object and no prose. The object must have exactly one key:
"order".

"order" must contain every supplied candidate exactly once. Each entry must
have exactly "region_id", "reason", and "evidence_ids". Use only region IDs
and evidence IDs supplied in the candidate JSON. Do not invent an address,
symbol, call, behavior, severity, or vulnerability. A reason may state that
the evidence is weak.

This is {REVIEW_PROMPT_ID}. You are proposing an order, not changing the
deterministic scores or proving a security finding."""


class ReviewError(ValueError):
    """A briefing or model review failed the strict review contract."""


def normalize_review_mode(mode: str) -> Literal["rules", "llm", "both"]:
    """Normalize a public mode name; ``compare`` is an alias for ``both``."""

    normalized = mode.strip().lower()
    if normalized == "compare":
        normalized = "both"
    if normalized not in {"rules", "llm", "both"}:
        raise ReviewError("mode must be one of: rules, llm, both, compare")
    return normalized  # type: ignore[return-value]


def review_briefing(
    briefing: Mapping[str, Any],
    *,
    mode: ReviewMode | str = "rules",
    thesis: str | None = None,
    bridge: LLMBridge | None = None,
    config: AppConfig | None = None,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Review known regions without modifying deterministic briefing output.

    ``rules`` copies the existing point-table order and makes no model call.
    ``llm`` adds a strictly validated model order. ``both`` also computes rank
    disagreements. Tool execution is deliberately disabled in this first
    contract version.
    """

    selected_mode = normalize_review_mode(str(mode))
    if bridge is not None and (config is not None or config_path is not None):
        raise ReviewError("Pass bridge or config/config_path, not both")
    if config is not None and config_path is not None:
        raise ReviewError("Pass config or config_path, not both")

    document = _json_object(briefing, "briefing")
    if document.get("schema_version") != "r2b.briefing.v1":
        raise ReviewError("briefing must use schema_version r2b.briefing.v1")
    candidates, evidence_by_region = _candidate_documents(document)
    base_order = _base_order(document, evidence_by_region)
    canonical_briefing = _canonical_json(document)
    canonical_candidates = _canonical_json({"candidates": candidates})
    result: dict[str, Any] = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "prompt_id": REVIEW_PROMPT_ID,
        "mode": selected_mode,
        "thesis": (thesis or "").strip() or None,
        "briefing": {
            "schema_version": "r2b.briefing.v1",
            "sha256": hashlib.sha256(canonical_briefing).hexdigest(),
            "candidate_sha256": hashlib.sha256(canonical_candidates).hexdigest(),
        },
        "candidate_count": len(candidates),
        "base_order": base_order,
        "model_order": None,
        "disagreements": [],
        "model": None,
    }
    if selected_mode == "rules":
        return result

    llm = bridge
    if llm is None:
        loaded = config or load_config(
            Path(config_path).expanduser() if config_path is not None else None
        )
        llm = LLMBridge(loaded)
    question = (thesis or "").strip() or "Prioritize these regions for first-pass binary triage."
    prompt_payload = {
        "thesis": question,
        # Canonical ID order prevents the deterministic point order from
        # anchoring the independent model review.
        "candidates": candidates,
    }
    try:
        response = llm.generate(
            [
                ChatMessage(role="system", content=_MODEL_SYSTEM),
                ChatMessage(
                    role="user",
                    content=json.dumps(
                        prompt_payload,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                ),
            ],
            tools=(),
            max_tool_rounds=0,
        )
    except LLMError:
        raise
    except Exception as exc:
        raise ReviewError(f"model review failed: {type(exc).__name__}: {exc}") from exc
    if not isinstance(response, LLMResponse):
        raise ReviewError("model review must return a normalized LLMResponse")
    if response.tool_calls or response.tool_rounds:
        raise ReviewError("r2b.review.v1 does not permit model tool calls")

    model_order = _validated_model_order(
        response.text,
        expected_ids=[str(item["region_id"]) for item in base_order],
        evidence_by_region=evidence_by_region,
    )
    result["model_order"] = model_order
    result["model"] = _model_metadata(response)
    if selected_mode == "both":
        result["disagreements"] = _disagreements(base_order, model_order)
    return result


def _candidate_documents(
    briefing: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, frozenset[str]]]:
    regions = briefing.get("regions")
    if not isinstance(regions, list) or not regions:
        raise ReviewError("briefing must contain at least one candidate region")
    candidates: list[dict[str, Any]] = []
    evidence_by_region: dict[str, frozenset[str]] = {}
    for raw in regions:
        if not isinstance(raw, Mapping):
            raise ReviewError("every briefing region must be an object")
        region_id = str(raw.get("id") or "").strip()
        if not region_id:
            raise ReviewError("every briefing region must have a non-empty id")
        if region_id in evidence_by_region:
            raise ReviewError(f"briefing contains duplicate region id: {region_id}")
        score = raw.get("score")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ReviewError(f"region {region_id!r} must have a numeric score")

        evidence = _evidence_entries(region_id, raw)
        evidence_by_region[region_id] = frozenset(str(item["id"]) for item in evidence)
        snippet = raw.get("snippet")
        candidate: dict[str, Any] = {
            "region_id": region_id,
            "title": str(raw.get("title") or region_id),
            "why": str(raw.get("why") or ""),
            "tags": [str(tag) for tag in (raw.get("tags") or [])],
            "evidence": evidence,
        }
        if isinstance(snippet, Mapping):
            candidate["snippet"] = {
                key: snippet.get(key)
                for key in (
                    "source",
                    "kind",
                    "text",
                    "address",
                    "function",
                    "artifact_id",
                    "xref",
                )
                if snippet.get(key) is not None
            }
        candidates.append(candidate)
    candidates.sort(key=lambda item: str(item["region_id"]))
    return candidates, evidence_by_region


def _evidence_entries(region_id: str, region: Mapping[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = [
        {
            "id": f"region:{region_id}",
            "kind": "region",
            "description": "The complete evidence capsule supplied for this region.",
        }
    ]
    snippet = region.get("snippet")
    if isinstance(snippet, Mapping) and any(
        snippet.get(key) is not None for key in ("text", "address", "function", "artifact_id")
    ):
        entries.append(
            {
                "id": f"snippet:{region_id}",
                "kind": "snippet",
                "source": snippet.get("source"),
                "address": snippet.get("address"),
                "function": snippet.get("function"),
                "artifact_id": snippet.get("artifact_id"),
            }
        )
    seen = {str(item["id"]) for item in entries}
    refs = region.get("evidence_refs")
    for raw in refs if isinstance(refs, list) else []:
        if not isinstance(raw, Mapping):
            continue
        action = raw.get("action")
        digest = str(raw.get("output_sha256") or "")
        if not isinstance(action, int) or action < 1 or len(digest) != 64:
            continue
        evidence_id = f"action:{action}:{digest[:16]}"
        if evidence_id in seen:
            continue
        seen.add(evidence_id)
        entries.append(
            {
                "id": evidence_id,
                "kind": "adapter_action",
                "action": action,
                "result_ref": raw.get("result_ref"),
                "output_sha256": digest,
            }
        )
    return entries


def _base_order(
    briefing: Mapping[str, Any], evidence_by_region: Mapping[str, frozenset[str]]
) -> list[dict[str, Any]]:
    regions = briefing.get("regions")
    assert isinstance(regions, list)  # validated by _candidate_documents
    order: list[dict[str, Any]] = []
    for rank, raw in enumerate(regions, start=1):
        assert isinstance(raw, Mapping)  # validated by _candidate_documents
        region_id = str(raw["id"])
        order.append(
            {
                "rank": rank,
                "region_id": region_id,
                "title": str(raw.get("title") or region_id),
                "score": raw["score"],
                "evidence_id": f"region:{region_id}",
            }
        )
        if f"region:{region_id}" not in evidence_by_region[region_id]:  # pragma: no cover
            raise ReviewError(f"region {region_id!r} has no evidence capsule")
    return order


def _validated_model_order(
    text: str,
    *,
    expected_ids: list[str],
    evidence_by_region: Mapping[str, frozenset[str]],
) -> list[dict[str, Any]]:
    payload = _parse_model_json(text)
    if set(payload) != {"order"}:
        raise ReviewError("model JSON must contain exactly: order")
    raw_order = payload.get("order")
    if not isinstance(raw_order, list):
        raise ReviewError("model order must be an array")

    expected = set(expected_ids)
    seen: set[str] = set()
    order: list[dict[str, Any]] = []
    for rank, raw in enumerate(raw_order, start=1):
        if not isinstance(raw, Mapping) or set(raw) != {"region_id", "reason", "evidence_ids"}:
            raise ReviewError(
                "each model order entry must contain exactly: region_id, reason, evidence_ids"
            )
        region_id = str(raw.get("region_id") or "")
        if region_id not in expected:
            raise ReviewError(f"model returned unknown region id: {region_id or '<empty>'}")
        if region_id in seen:
            raise ReviewError(f"model returned duplicate region id: {region_id}")
        seen.add(region_id)
        reason = str(raw.get("reason") or "").strip()
        if not reason:
            raise ReviewError(f"model returned an empty reason for region: {region_id}")
        evidence_ids = raw.get("evidence_ids")
        if (
            not isinstance(evidence_ids, list)
            or not evidence_ids
            or not all(isinstance(item, str) and item for item in evidence_ids)
        ):
            raise ReviewError(f"model evidence_ids must be non-empty strings for region: {region_id}")
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ReviewError(f"model returned duplicate evidence ids for region: {region_id}")
        unknown_evidence = set(evidence_ids) - evidence_by_region[region_id]
        if unknown_evidence:
            names = ", ".join(sorted(unknown_evidence))
            raise ReviewError(f"model cited unknown evidence for region {region_id}: {names}")
        order.append(
            {
                "rank": rank,
                "region_id": region_id,
                "reason": reason,
                "evidence_ids": list(evidence_ids),
            }
        )
    missing = expected - seen
    if missing:
        raise ReviewError("model omitted region ids: " + ", ".join(sorted(missing)))
    if len(order) != len(expected_ids):  # pragma: no cover - duplicates/unknowns checked above
        raise ReviewError("model order is not an exact candidate permutation")
    return order


def _parse_model_json(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```json") and raw.endswith("```"):
        raw = raw[7:-3].strip()
    elif raw.startswith("```") and raw.endswith("```"):
        raw = raw[3:-3].strip()
    if not raw:
        raise ReviewError("model returned an empty review")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReviewError(f"model review is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ReviewError("model review must be a JSON object")
    return value


def _disagreements(
    base_order: list[dict[str, Any]], model_order: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    base_ranks = {str(item["region_id"]): int(item["rank"]) for item in base_order}
    disagreements = []
    for item in model_order:
        region_id = str(item["region_id"])
        base_rank = base_ranks[region_id]
        model_rank = int(item["rank"])
        if base_rank == model_rank:
            continue
        disagreements.append(
            {
                "region_id": region_id,
                "base_rank": base_rank,
                "model_rank": model_rank,
                # Positive means the model moved the region earlier.
                "rank_shift": base_rank - model_rank,
            }
        )
    disagreements.sort(key=lambda item: (-abs(int(item["rank_shift"])), int(item["model_rank"])))
    return disagreements


def _model_metadata(response: LLMResponse) -> dict[str, Any]:
    transport = response.transport.value
    return {
        "provider": response.provider,
        "model": response.model,
        "transport": transport,
        "response_id": response.response_id,
        "usage": asdict(response.usage),
        "finish_reason": response.finish_reason,
        "latency_ms": response.latency_ms,
        "tool_rounds": response.tool_rounds,
    }


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReviewError(f"review input is not JSON serializable: {exc}") from exc


def _json_object(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReviewError(f"{label} must be a JSON object")
    try:
        normalized = json.loads(_canonical_json(value))
    except json.JSONDecodeError as exc:  # pragma: no cover - canonical JSON is valid
        raise ReviewError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(normalized, dict):  # pragma: no cover - Mapping encodes as object
        raise ReviewError(f"{label} must be a JSON object")
    return normalized


__all__ = [
    "REVIEW_PROMPT_ID",
    "REVIEW_SCHEMA_VERSION",
    "ReviewError",
    "ReviewMode",
    "normalize_review_mode",
    "review_briefing",
]
