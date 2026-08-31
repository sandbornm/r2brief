# Provenance and replay

Every `AnalysisResult`, public analysis payload, and briefing can carry
`r2b.provenance.v1`. It is the small, filesystem-independent answer to “how
did r2b produce this evidence?” SQLite trajectories remain useful for session
history, but they are not required to inspect or replay a result.

The provenance object records:

- input name, byte size, and SHA-256;
- the resolved analysis plan and a secret-free snapshot of analysis settings;
- adapter availability and final status;
- ordered quick/deep actions, each linked to its evidence bag by JSON pointer;
- a SHA-256 of each referenced adapter payload; and
- copyable shell and Python recipes.

Region evidence links back to action sequence numbers. For example, a region
with `snippet.source == "radare2"` includes `evidence_refs` pointing to both
`/quick_scan/radare2` and `/deep_scan/radare2` when both passes contributed.
Large disassembly or decompiler output is not duplicated in provenance.

```python
from pathlib import Path

from r2b import analyze
from r2b.analysis.provenance import render_replay_python

report = analyze("./samples/bin/arm64/vulnerable")
recipe = report.payload["provenance"]

print(recipe["input"]["sha256"])
for action in recipe["actions"]:
    print(action["sequence"], action["action"], action["result_ref"])

Path("replay.py").write_text(render_replay_python(recipe))
```

The generated Python recipe rebuilds the captured, secret-free configuration,
runs the public API, and asserts the input SHA-256. Set `R2B_INPUT` to replay
against a relocated copy. The shell recipe uses the same variable but uses the
current configuration; use the Python recipe when exact analyzer gates and
extraction bounds matter.

This is intentionally a recipe rather than a planner. It does not invent new
steps, execute a model, or claim deterministic output from tools whose own
versions or runtime environments differ. `adapter_status` makes those tool gaps
visible for comparison.

## Export container integration

A portable `.r2br` export should store this object as `provenance.json` and
retain the referenced `quick_scan`/`deep_scan` paths in its analysis payload.
Bundle code should consume `AnalysisResult.provenance` (or the public payload's
`provenance`) rather than rebuilding a second action model. The authoritative
schema is [`schemas/provenance.schema.json`](../schemas/provenance.schema.json).
