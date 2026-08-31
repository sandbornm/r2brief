# Portable evidence bundles (`.r2br`)

An `.r2br` file is a small, versioned handoff between r2b, a human reviewer,
and an external harness. It packages the ranked briefing, public analysis
payload, tool status, hashes, and available provenance without requiring the
recipient to share r2b's SQLite state or filesystem layout.

One bundle describes one analyzed subject at one point in time. Corpus state
lives in the content-addressed record store. `r2b insights` compares tagged
record siblings; it does not read a directory of bundles as a similarity
database. The current corpus report covers exact SHA-256 identity, recurring
imports, ranked regions, tags, and firmware wrapper families. It does not
contain fuzzy similarity clusters, learned behavior groups, or predictions for
new binaries.

The extension is a convention, not the type check. Readers open the ZIP and
require a valid `manifest.json` with `schema_version: r2b.bundle.v1`; renaming a
valid bundle does not break inspection, and a random ZIP renamed to `.r2br`
does not become a bundle.

## Create and inspect

```bash
# Quick analysis. The binary is hashed, but its bytes are not embedded.
r2b bundle create ./samples/triage/bin/shallow-host -o shallow.r2br

# Validate every member against the manifest and print a concise summary.
r2b bundle inspect shallow.r2br
r2b bundle inspect shallow.r2br --json

# Explicit opt-in for a self-contained bundle when redistribution is allowed.
r2b bundle create ./sample.bin -o sample.r2br --include-target
```

Library callers can use the same contract:

```python
from r2b.bundle import create_bundle, read_bundle

created = create_bundle(
    "sample.r2br",
    briefing=briefing,
    analysis=public_analysis,
    tool_status=public_analysis["tool_status"],
    target="sample.bin",          # establishes SHA-256 + size
    include_target=False,          # the default
)
loaded = read_bundle(created.path) # validates paths, sizes, and hashes
print(loaded.briefing["regions"])
```

## Layout

```text
sample.r2br (deterministic ZIP)
├── mimetype         exact uncompressed media-type sentinel (always first)
├── manifest.json    r2b.bundle.v1, subject address, member hashes
├── analysis.json    public r2b.analysis_result.v1 payload
├── briefing.json    ranked r2b.briefing.v1 + r2b.handoff.v1
├── tools.json       availability/status captured during the run
├── provenance.json  public provenance, when present
└── target.bin       optional; present only with --include-target
```

`manifest.json` also carries `handoff.requires_scope` when available;
`provenance.json` copies the public analysis provenance without reconstructing
private trajectory state. This preserves the useful answer
to “how was this produced?” without copying the internal trajectory database
or turning r2b into the planner.

The JSON Schema for the manifest is
[`schemas/evidence_bundle.schema.json`](../schemas/evidence_bundle.schema.json).

## Safety and determinism

- Every payload member is content-addressed with SHA-256 and checked on read.
- Byte zero starts a conforming ZIP. Its first entry is the uncompressed,
  extra-field-free `mimetype` sentinel containing exactly
  `application/vnd.r2brief.bundle+zip` (no newline).
- Member names are allowlisted; absolute paths, traversal, duplicates,
  directories, encryption, unknown compression, and oversized members fail
  closed.
- ZIP timestamps and permissions are fixed, members are sorted, and JSON is
  canonicalized. Identical inputs on the same r2b version produce identical
  bundle bytes.
- Target bytes are excluded by default. The manifest still records their
  basename, size, and SHA-256 so another operator can match evidence to a file
  already in their custody.

The format is an interchange artifact, not a replacement for an IDA database,
Ghidra project, memory image, or full execution trace. Large targets such as a
browser engine are better split into scoped subjects or analyzed in their
native project; the bundle should carry the selected evidence and reproduction
context, not every byte and intermediate object by default.
