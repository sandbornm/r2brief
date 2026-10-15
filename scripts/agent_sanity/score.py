"""Score an agent transcript + final JSON against a golden expected.json."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_R2B_EXEC_RE = re.compile(r"(?:\./)?r2b-exec\s+([^\n`]+)")
_DENIED = {"--ask", "--ask-regions", "--review-lens"}


def score_run(
    *,
    golden: dict[str, Any],
    transcript: str,
    final_answer: str | dict[str, Any] | None,
    elapsed_s: float,
    step_count: int | None = None,
) -> dict[str, Any]:
    score = golden.get("agent_score") or {}
    checks: dict[str, bool] = {}
    notes: list[str] = []

    text = transcript or ""
    answer_text = (
        json.dumps(final_answer)
        if isinstance(final_answer, dict)
        else (final_answer or "")
    )
    blob = text + "\n" + answer_text

    cmds = _R2B_EXEC_RE.findall(text)
    if step_count is None:
        step_count = len(cmds)

    # Allowlist: every shell-ish r2b-exec line should start with a known verb.
    allow = True
    for raw in cmds:
        head = raw.strip().split()
        if not head:
            continue
        if head[0] not in {
            "env",
            "setup",
            "brief",
            "verify",
            "diff",
            "decompile",
            "records",
            "insights",
            "review",
            "bundle",
            "ghidra",
            "version",
            "--version",
            "--help",
            "-h",
        }:
            allow = False
            notes.append(f"non-allowlisted: {head[0]}")
        joined = " ".join(head)
        for flag in _DENIED:
            if flag in joined or "--mode llm" in joined or "--mode both" in joined:
                allow = False
                notes.append(f"model flag in transcript: {flag}")
    checks["allowlist_only"] = allow if score.get("allowlist_only", True) else True

    # No model calls from r2b: no --ask / llm review in transcript.
    checks["no_r2b_model"] = not any(
        tok in text for tok in ("--ask", "--mode llm", "--mode both", "--review-lens")
    )

    if "must_changed_relpaths" in score:
        need = set(score["must_changed_relpaths"])
        checks["right_files"] = need <= set(re.findall(r"[\w./-]+", blob))
        # also accept if reduction JSON embedded
        for path in need:
            if path not in blob:
                checks["right_files"] = False
    if "must_reduction" in score:
        ok = True
        for key, value in score["must_reduction"].items():
            if f'"{key}": {value}' not in blob and f'"{key}":{value}' not in blob:
                # softer: look for the number near the key
                if not re.search(rf"{key}[^\d]{{0,20}}{value}", blob):
                    ok = False
        checks["right_reduction"] = ok
    if "must_name_sink" in score:
        checks["right_sink"] = score["must_name_sink"] in blob
    if "must_name_import" in score:
        checks["right_import"] = score["must_name_import"] in blob
    if "must_tags_cwe" in score:
        checks["right_cwe"] = all(x in blob for x in score["must_tags_cwe"])
    if "must_tags_tid" in score:
        checks["right_tid"] = all(x in blob for x in score["must_tags_tid"])

    max_steps = int(score.get("max_steps") or 20)
    max_seconds = float(score.get("max_seconds") or 300)
    checks["within_steps"] = step_count <= max_steps
    checks["within_time"] = elapsed_s <= max_seconds

    passed = all(checks.values()) if checks else False
    return {
        "passed": passed,
        "checks": checks,
        "notes": notes,
        "step_count": step_count,
        "elapsed_s": elapsed_s,
        "commands_seen": cmds[:20],
    }
