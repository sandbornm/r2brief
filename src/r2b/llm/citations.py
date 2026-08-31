"""Ground AI claims in artifact IDs, addresses, xrefs, and the establishing tool.

Cite tag (one per claim bullet)::

    [tool=radare2 addr=0x7a8 artifact=n:function:ab12 xref=puts]

Model-invented names and types are proposals, not facts.
"""

from __future__ import annotations

import re
from typing import Any

CITE_TAG_RE = re.compile(
    r"\[(?:cite:?\s*)?tool=(?P<tool>[\w.-]+)"
    r"(?:\s+addr=(?P<addr>0x[0-9a-fA-F]+))?"
    r"(?:\s+artifact=(?P<artifact>[^\s\]]+))?"
    r"(?:\s+xref=(?P<xref>[^\s\]]+))?\]",
    re.IGNORECASE,
)

PROPOSED_RE = re.compile(r"\bproposed\b", re.IGNORECASE)
_BULLET_RE = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+")


def format_cite(
    *,
    tool: str,
    addr: str | None = None,
    artifact: str | None = None,
    xref: str | None = None,
) -> str:
    parts = [f"tool={tool}"]
    if addr:
        parts.append(f"addr={addr}")
    if artifact:
        parts.append(f"artifact={artifact}")
    if xref:
        parts.append(f"xref={xref}")
    return "[" + " ".join(parts) + "]"


def parse_cites(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for match in CITE_TAG_RE.finditer(text or ""):
        found.append({key: value for key, value in match.groupdict().items() if value})
    return found


def parse_cited_claims(text: str) -> dict[str, Any]:
    """Split an LLM answer into cited claims vs uncited / proposed-only lines."""
    claims: list[dict[str, Any]] = []
    uncited: list[str] = []
    proposed: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not _BULLET_RE.match(line) and not CITE_TAG_RE.search(line):
            continue
        stripped = _BULLET_RE.sub("", line).strip()
        cites = parse_cites(stripped)
        claim_text = CITE_TAG_RE.sub("", stripped).strip()
        is_proposed = bool(PROPOSED_RE.search(claim_text))
        if is_proposed:
            proposed.append(claim_text)
        if cites:
            claims.append({"text": claim_text, "cites": cites, "proposed": is_proposed})
        elif _looks_like_claim(claim_text):
            uncited.append(claim_text)
    return {
        "schema_version": "r2b.cited_claims.v1",
        "claims": claims,
        "uncited": uncited,
        "proposed": proposed,
        "grounded": bool(claims) and not uncited,
    }


def proposed_annotations_from_claims(cited: dict[str, Any]) -> list[dict[str, Any]]:
    """Rows for proposed_annotations: invented names/types only, still cited."""
    rows: list[dict[str, Any]] = []
    for claim in cited.get("claims") or []:
        if not isinstance(claim, dict) or not claim.get("proposed"):
            continue
        cites = [c for c in (claim.get("cites") or []) if isinstance(c, dict)]
        cite = cites[0] if cites else {}
        text = str(claim.get("text") or "").strip()
        if not text:
            continue
        kind = "name" if re.search(r"\bname\b", text, re.IGNORECASE) else "claim"
        rows.append(
            {
                "kind": kind,
                "address": cite.get("addr"),
                "artifact_id": cite.get("artifact"),
                "tool": cite.get("tool"),
                "xref": cite.get("xref"),
                "payload": {"text": text, "cites": cites},
                "status": "proposed",
                "source": "llm",
            }
        )
    return rows


def evidence_block(
    *,
    tool: str | None,
    addr: str | None = None,
    artifact: str | None = None,
    xref: str | None = None,
) -> str:
    """Compact list of IDs the model is allowed to cite for this region."""
    lines = ["Cite each claim as [tool=NAME addr=0x… artifact=ID xref=SYM]. Invented names/types: prefix proposed."]
    cite = format_cite(tool=tool or "unknown", addr=addr, artifact=artifact, xref=xref)
    lines.append(f"Evidence: {cite}")
    return "\n".join(lines)


def _looks_like_claim(text: str) -> bool:
    if len(text) < 12:
        return False
    lowered = text.lower()
    if lowered.startswith("rules:") or lowered.startswith("answer in"):
        return False
    if "next command" in lowered and "exact" in lowered:
        return False
    return True


__all__ = [
    "CITE_TAG_RE",
    "evidence_block",
    "format_cite",
    "parse_cited_claims",
    "parse_cites",
    "proposed_annotations_from_claims",
]
