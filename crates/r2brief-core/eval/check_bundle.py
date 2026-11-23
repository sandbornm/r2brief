"""Validate an r2brief-core .r2br against the repo's JSON schemas.

Reads the bundle with r2b's own reader (paths, sizes, hashes), then checks
manifest / briefing / provenance against schemas/*.schema.json with a small
draft-2020-12 subset validator (the keywords those schemas use), so CI needs
no extra dependency.

Usage: uv run python crates/r2brief-core/eval/check_bundle.py BUNDLE.r2br
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from r2b.bundle import read_bundle

SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "integer": int, "number": (int, float), "null": type(None),
}


def _is(v, t: str) -> bool:
    if t in ("integer", "number") and isinstance(v, bool):
        return False
    return isinstance(v, TYPES[t])


def validate(v, s: dict, path: str, errs: list[str]) -> None:
    if "$ref" in s:
        validate(v, json.loads((SCHEMAS / s["$ref"]).read_text()), path, errs)
    if "type" in s:
        ts = s["type"] if isinstance(s["type"], list) else [s["type"]]
        if not any(_is(v, t) for t in ts):
            errs.append(f"{path}: type {type(v).__name__} not in {ts}")
            return
    if "const" in s and v != s["const"]:
        errs.append(f"{path}: {v!r} != const {s['const']!r}")
    if "enum" in s and v not in s["enum"]:
        errs.append(f"{path}: {v!r} not in enum")
    if isinstance(v, str):
        if "pattern" in s and not re.search(s["pattern"], v):
            errs.append(f"{path}: {v!r} !~ {s['pattern']}")
        if len(v) < s.get("minLength", 0):
            errs.append(f"{path}: shorter than minLength")
    if _is(v, "number") and "minimum" in s and v < s["minimum"]:
        errs.append(f"{path}: {v} < minimum {s['minimum']}")
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append(f"{path}: missing required {k!r}")
        props = s.get("properties", {})
        for k, sub in props.items():
            if k in v:
                validate(v[k], sub, f"{path}/{k}", errs)
        ap = s.get("additionalProperties", True)
        for k in v:
            if k not in props:
                if ap is False:
                    errs.append(f"{path}: unexpected property {k!r}")
                elif isinstance(ap, dict):
                    validate(v[k], ap, f"{path}/{k}", errs)
    if isinstance(v, list):
        if len(v) < s.get("minItems", 0) or len(v) > s.get("maxItems", len(v)):
            errs.append(f"{path}: item count {len(v)} out of range")
        if s.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in v}) != len(v):
            errs.append(f"{path}: items not unique")
        if isinstance(s.get("items"), dict):
            for i, x in enumerate(v):
                validate(x, s["items"], f"{path}/{i}", errs)


def main(argv: list[str]) -> int:
    b = read_bundle(argv[1])
    errs: list[str] = []
    for name, doc, schema in (
        ("manifest", b.manifest, "evidence_bundle.schema.json"),
        ("briefing", b.briefing, "briefing.schema.json"),
        ("provenance", b.provenance, "provenance.schema.json"),
    ):
        if doc is None:
            errs.append(f"{name}: missing from bundle")
            continue
        validate(doc, json.loads((SCHEMAS / schema).read_text()), name, errs)
    for e in errs:
        print("FAIL", e, file=sys.stderr)
    print(json.dumps({"bundle": str(b.path), "sha256": b.sha256, "schema_errors": len(errs)}))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
