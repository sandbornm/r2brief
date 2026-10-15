"""Score an agent transcript + final JSON against a golden expected.json."""

from __future__ import annotations

import json
import re
from typing import Any

_CMD_JSON_RE = re.compile(
    r'"type"\s*:\s*"command_execution"[^}]*?"command"\s*:\s*"(?P<cmd>(?:\\.|[^"\\])*)"'
)
_CMD_PLAIN_RE = re.compile(r"(?:^|[^\w./-])((?:\./)?r2b-exec)\s+([^\n`\"']+)")
_DENIED_IN_ARGV = re.compile(
    r"(?:--ask(?:-regions)?\b|--review-lens\b|--mode\s*=?\s*(?:llm|both|compare)\b|"
    r"--review-mode\s*=?\s*(?:llm|both|compare)\b)"
)


def _extract_commands(transcript: str) -> list[str]:
    """Prefer structured command_execution payloads; fall back to plain r2b-exec lines."""
    cmds: list[str] = []
    for match in _CMD_JSON_RE.finditer(transcript or ""):
        raw = bytes(match.group("cmd"), "utf-8").decode("unicode_escape")
        # Keep only the r2b-exec argv portion if wrapped in a shell.
        if "r2b-exec" in raw:
            cmds.append(raw[raw.index("r2b-exec") :])
        else:
            cmds.append(raw)
    if cmds:
        return cmds
    for match in _CMD_PLAIN_RE.finditer(transcript or ""):
        cmds.append((match.group(1) + " " + match.group(2)).strip())
    return cmds


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
    # Score facts against final answer + agent_message text, not tool noise.
    blob = answer_text
    for match in re.finditer(r'"type"\s*:\s*"agent_message".*?"text"\s*:\s*"(?P<t>(?:\\.|[^"\\])*)"', text):
        try:
            blob += "\n" + bytes(match.group("t"), "utf-8").decode("unicode_escape")
        except Exception:
            blob += "\n" + match.group("t")
    if not blob.strip():
        blob = text

    cmds = _extract_commands(text)
    if step_count is None:
        step_count = len(cmds)

    allow = True
    model_in_cmd = False
    for raw in cmds:
        head = raw.replace("./", "").strip().split()
        if not head:
            continue
        # head[0] may be r2b-exec
        verb_idx = 0
        if head[0].endswith("r2b-exec"):
            verb_idx = 1
        if verb_idx >= len(head):
            continue
        verb = head[verb_idx]
        if verb not in {
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
            notes.append(f"non-allowlisted: {verb}")
        if _DENIED_IN_ARGV.search(raw):
            model_in_cmd = True
            notes.append(f"model flag in command: {raw[:80]}")
    checks["allowlist_only"] = allow if score.get("allowlist_only", True) else True
    checks["no_r2b_model"] = (not model_in_cmd) if score.get("no_r2b_model", True) else True

    if "must_changed_relpaths" in score:
        need = set(score["must_changed_relpaths"])
        checks["right_files"] = all(path in blob for path in need)
    if "must_reduction" in score:
        ok = True
        for key, value in score["must_reduction"].items():
            if f'"{key}": {value}' not in blob and f'"{key}":{value}' not in blob:
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
