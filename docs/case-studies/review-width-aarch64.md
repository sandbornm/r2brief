# Review width on three AArch64 programs

This case asks whether several independent readings of one evidence set produce
useful extra coverage. The inputs are BusyBox, dnsmasq, and uHTTPD from the same
OpenWrt 24.10 AArch64 package feed. They are stripped, sectionless ELF programs
with different jobs and sizes.

The short answer is yes, with a limit. A second lens exposed the runtime-loading
capsule in BusyBox and uHTTPD. It added nothing to dnsmasq's top two. A third
lens brought memory and path handling into view on all three. That flat step on
dnsmasq matters: width is a budget, not a promise of a new finding.

## Depth and width are different controls

Analysis depth collects evidence. `--quick` and the deeper adapters change what
r2b knows about the file.

Review width asks more questions of evidence already in the briefing. It does
not run another analyzer or alter the point-table scores. Every lens receives
the same candidate and evidence IDs. The passes run independently, then r2b
deduplicates their cited evidence and builds the overlay.

The implementation uses fan-out and merge. One lens never sees another lens's
answer. Feeding answers forward would reward repetition and make three copies of
one guess look like corroboration.

## Inputs

| Program | Size | Functions | Imports | SHA-256 |
|---|---:|---:|---:|---|
| OpenWrt BusyBox 1.36.1-r3 | 458,773 | 301 | 299 | `d3aeb34a…e90b66f` |
| OpenWrt dnsmasq 2.93-r1 | 334,841 | 170 | 175 | `a433c23c…3d84d7f` |
| OpenWrt uHTTPD `7e64e8ba-r5` | 66,259 | 116 | 117 | `2dea2e10…da1b0941` |

[`scripts/fetch_case_studies.sh`](../../scripts/fetch_case_studies.sh) pins and
checks both each package and its extracted binary. The targets were not run.

## The shared evidence capsules

The old quick brief put every interesting import into `imports:plt`. That left
these programs with two review candidates: the import bucket and the entry
point. More lenses could only swap those two rows.

The briefing now keeps the same radare2 import inventory but emits separate
capsules when the evidence exists:

- `imports:process`: child creation and process launch
- `imports:network`: network ingress and egress
- `imports:runtime`: runtime loading and mapped memory
- `imports:memory`: memory and path handling
- `imports:control`: kernel and identity controls

These are pivots, not behavior claims. `strcpy` remains an imported name until a
caller and data flow establish more. `dlopen` remains a runtime-loading lead
until a path and caller are recovered.

## Recorded width run

The case used rules mode, width 3, and the top two regions from each pass. No
model was called.

```sh
r2b bundle create "$BIN" \
  --review-width 3 \
  --review-mode rules \
  --review-top 2 \
  --output "$NAME-width3.r2br"
```

| Program | Width 1: triage | Width 2: execution boundaries | Width 3: input to effect |
|---|---|---|---|
| BusyBox | process, network | + runtime | + memory/path |
| dnsmasq | process, network | no new top region | + memory/path |
| uHTTPD | process, network | + runtime | + memory/path |

The raw recorded summary is
[`results/review-width-aarch64.json`](results/review-width-aarch64.json).

Agreement is counted by lens, not by pass. If a rules pass and a model pass for
the same lens both cite `imports:process`, that is one lens reaching one known
evidence capsule. The overlay records rank spread separately so disagreement
stays visible.

## Optional model lenses

Rules mode makes the feature reproducible and useful without a model. `llm`
and `both` use the provider already selected by the r2b overlay. A custom model
lens is a repeatable `--review-lens` value:

```sh
r2b bundle create "$BIN" \
  --review-width 3 \
  --review-mode both \
  --review-lens 'Trace network-controlled data toward process launch.' \
  --review-lens 'Find behavior controlled by files or runtime configuration.' \
  --review-lens 'Prioritize gaps that need a caller, decompile, or runtime fact.' \
  --output "$NAME-width3.r2br"
```

Each model response must return an exact permutation of known region IDs and
cite evidence IDs assigned to those regions. Unknown IDs, missing regions, and
tool calls fail closed. The provider, model, usage, and latency are recorded per
pass. Model prose remains a proposal.

## What the bundle adds

The resulting `.r2br` keeps one subject and one immutable analysis snapshot.
`review.json` adds the lenses, individual orders, unique evidence IDs,
agreement, conflicts, and the regions first exposed at each width. Target bytes
remain excluded unless `--include-target` is explicit.

This is useful when a person or harness needs to choose among a few bounded
follow-ups. It is not useful when the briefing has only one meaningful capsule,
or when the real need is deeper evidence. In those cases, move from quick to a
targeted verifier or decompile instead of increasing width.
