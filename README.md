<p align="center">
  <img src="docs/brand/logo.svg" alt="r2brief" width="238" />
</p>

<p align="center">
  <strong>Get a bounded first pass on an unfamiliar binary before opening a full RE project.</strong><br />
  r2b keeps the evidence, ranks a few places to inspect, and prints the next commands.
</p>

<p align="center">
  <a href="https://github.com/sandbornm/r2brief/actions/workflows/ci.yml"><img src="https://github.com/sandbornm/r2brief/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
</p>

`r2b` accepts ELF, PE, Mach-O, firmware, containers, and raw blobs through a
CLI, Python library, web workbench, or subprocess harness. It detects the tools
on the host and records missing prerequisites as skips. The default path does
not execute the target or call a model.

```bash
git clone https://github.com/sandbornm/r2brief.git
cd r2brief
./scripts/install.sh
uv run r2b brief samples/triage/bin/shallow-host --quick --no-save --json
```

The installer creates an environment inside the checkout. It does not modify
the system Python.

## What comes out

| Input | Result |
|---|---|
| One executable | format and architecture, tool coverage, ranked regions, evidence references, and exact follow-up commands |
| Firmware or a container | bounded inventory, carved-child recommendations, and an artifact DAG with offsets and hashes |
| A saved analysis | one SHA-256-addressed record that can absorb later passes without losing earlier evidence |
| A handoff | one validated `.r2br` bundle with the briefing, public analysis, tool status, hashes, replay data, and an optional review overlay |
| Tagged sibling records | exact duplicates and recurring imports, regions, tags, or firmware wrapper families |

Region scores are ordering points from fixed rules. They are not probabilities,
severity ratings, or vulnerability findings. An import or string is a lead. A
behavior claim needs a caller and relevant data flow; an observed behavior also
needs runtime evidence.

r2b is not a general behavior checker or a binary SAST engine. `r2b verify`
answers one narrow question: what can the static caller analysis recover for
the first argument passed to selected process-launch imports? The project does
not yet provide whole-program taint analysis, vulnerability rules, or a policy
engine for arbitrary behaviors.

### Corpus results today

Each saved target becomes a content-addressed record. Repeated analysis of the
same bytes updates that record. Tags define sibling sets for comparison:

```bash
r2b brief ./image-a/httpd --quick --tag httpd --json
r2b brief ./image-b/httpd --quick --tag httpd --json
r2b insights --tag httpd --json
```

`insights` separates executables from container families, collapses identical
SHA-256 values, and reports evidence that recurs in at least two siblings. It
does not yet compute fuzzy binary similarity, function similarity, behavior
clusters, embeddings, or predictions for an unseen binary. The per-subject
evidence graph and artifact DAG are factual maps, not a learned corpus
knowledge graph.

A future corpus-similarity layer would need to explain every edge with
measurable support such as exact content, function fingerprints, import-set
overlap, shared configuration, or confirmed runtime behavior. Until that exists
and is calibrated, r2b does not call a group of files behaviorally similar.

### The `.r2br` file

An `.r2br` contains one analysis snapshot. It is not the corpus database.
Target bytes are excluded unless `--include-target` is set.

```text
sample.r2br
├── mimetype         file-type sentinel
├── manifest.json    subject hash, member hashes, producer version
├── analysis.json    normalized evidence and artifact graph
├── briefing.json    ranked regions and next argv
├── tools.json       completed and skipped tools
├── provenance.json  evidence pointers and replay recipe, when available
├── review.json      optional independent-lens review overlay
└── target.bin       optional
```

```bash
r2b bundle create ./httpd -o httpd.r2br
r2b bundle create ./httpd -o httpd-width3.r2br --review-width 3 --review-mode rules
r2b bundle inspect httpd.r2br --json
r2b review httpd.r2br --mode rules --json
```

The reader validates member names, sizes, and SHA-256 values. Identical inputs
on the same r2b version produce identical bundle bytes. See
[the bundle contract](docs/BUNDLES.md) and [provenance rules](docs/PROVENANCE.md).

## What r2b adds to radare2

r2b does not disassemble better than radare2. It uses radare2 for the routine
code map, then adds the workflow around it:

| r2b owns | r2b delegates |
|---|---|
| bounded format and firmware classification | functions, imports, strings, CFGs, and xrefs from radare2 |
| adapter selection and explicit skip records | one-function decompilation and types from Ghidra |
| artifact DAG, evidence IDs, ranking, and handoff argv | targeted symbolic work from angr |
| records, corpus comparisons, bundles, and replay data | explicit runtime inspection from Frida or GEF |
| optional rules/model rank comparison | extraction from binwalk3 or unblob |

The default `analyze()` profile is deliberately mechanical. It reads format
headers, runs the bounded file/runtime checks, then uses r2pipe to start
radare2 and request metadata, imports, strings, sections, symbols, entry points,
and 32 bytes at the selected entry. `build_briefing()` turns those evidence
classes into fixed-point candidates, sorts them, and emits the handoff. It does
not infer whole-program behavior or estimate vulnerability likelihood.

The `standard` and `exhaustive` profiles can add the enabled deep adapters after
that intake. Frida and GEF remain explicit because they execute or attach to a
target. No profile calls a model as part of analysis.

Without radare2, r2b can still classify formats, inventory firmware, run
bounded extraction, preserve records, and create bundles. Executable triage is
much shallower because functions, xrefs, and the normal code map are missing.

If the target is already open at the right function in r2 or Ghidra, stay
there. r2b earns its place when the scope is unclear, the inputs are numerous,
the hosts differ, or another person or program needs the same evidence in a
stable format.

## Worked investigation

The [OpenWrt uHTTPD investigation](docs/case-studies/uhttpd-aarch64.md) starts with
a pinned 66 KB AArch64 package, not a teaching binary. The quick pass reduced
116 functions and 117 imports to a few evidence capsules. The process capsule
gave the useful first command:

```text
subject       ELF64 AArch64 PIE · musl · stripped · no section table
regions       1. Process launch / child control   score 93
              2. Network ingress and egress       score 90
              3. Entry / entry @ 0x4b0c           score 89
handoff       r2b verify ./uhttpd --import execl --json
recovered     reloc.execl @ 0x1fb60 → blr x4 @ 0x9384
caller        fcn.000092e4 · argument=<dynamic>
target run    no
models called no
```

Pinned source showed normal CGI dispatch: path lookup and authentication lead
to a forked child that calls `execl` directly rather than building a shell
command. The binary establishes that execution boundary; it does not establish
a vulnerability. The remaining question belongs to the deployed router: who
can create or replace an executable CGI path?

The first verifier run missed the GOT-indirect AArch64 call. The original empty
result remains in the investigation record. The recovered instruction pattern
now has a regression test. The bundled crackmes and algorithm samples stay in
[calibration](docs/calibration/teaching-fixtures.md), where they test ordering,
weak results, and known limits rather than serving as product proof.

Build and check those fixtures locally:

```bash
./samples/triage/build.sh
uv run pytest -q tests/unit/test_triage_samples.py tests/unit/test_binary_formats.py \
  tests/integration/test_sample_briefs.py
```

[GNU Hello](docs/calibration/hello-aarch64.md) is the benign control for
import-risk noise.

## Install and use

```bash
./scripts/install.sh                  # choose core, lab, or full for this host
uv run r2b setup --json               # chosen flavor and setup timing
uv run r2b env --json                 # available and skipped adapters

r2b brief ./httpd --quick --no-save --json
r2b verify ./httpd --import popen --json
r2b decompile ./httpd 0x12a40 --json
r2b brief firmware.bin --quick --extract --json
r2b records list --json
r2b insights --tag lab --json
```

`core` and `lab` install the routine radare2 path. `full` adds Python analyzer
dependencies on a suitable workstation. Ghidra, binwalk3, unblob, Frida, GEF,
and QEMU remain detected host tools or explicit capabilities. Installation
details are in [docs/install.md](docs/install.md); command behavior and limits
are in [docs/USAGE.md](docs/USAGE.md) and [docs/LIMITS.md](docs/LIMITS.md).

`--json` reserves stdout for structured output and sends diagnostics to stderr.
The stable harness contract is documented in [docs/HARNESS.md](docs/HARNESS.md).

## Python and models

Library analysis is non-persistent and model-free by default:

```python
from r2b import AnalysisOptions, analyze

report = analyze("./sample.bin", options=AnalysisOptions(profile="triage"))
for region in report.regions:
    print(region.id, region.score, region.evidence)
for command in report.handoff["next_argv"]:
    print(command)
```

`report.ask(...)`, `--ask`, and `review --mode llm|both` are separate opt-in
model calls. Rules mode makes no model call. Both mode keeps the fixed order and
records a validated model order against the same region and evidence IDs. The
model cannot add, remove, or rename evidence.

`review --width N` runs `N` independent lenses over one saved briefing.
Each lens starts from the same candidates. The `r2b.review-set.v1` overlay shows
which regions first appeared at each width and when another pass added nothing.
Rules mode is deterministic; `llm` and `both` use the configured provider.

OpenAI, Anthropic, xAI/Grok, Kimi, GLM/Z.ai, Ollama, and exo have explicit
provider configurations. Hosted keys are read from named environment variables
or `.env`, never committed TOML. The host must provide an executor, allowlist,
and round limit before declared function tools can run. MCP is optional because
the CLI and Python API already provide harness boundaries. See
[model configuration](docs/USAGE.md#pointing-at-a-model) and
[the architecture](docs/ARCHITECTURE.md).

## Repository layout

```text
src/r2b/               CLI, public API, orchestration, adapters, records, web server
web/frontend/          React workbench; built assets ship in the standard wheel
config/                install flavors and provider examples; no secrets
schemas/               versioned JSON contracts
samples/triage/        shallow C fixture and cross-target build harness
ghidra/extensions/r2b/ optional Ghidra extension and scripts
scripts/               isolated setup, install, packaging, and environment checks
docs/                  contracts, case studies, architecture, deployment, and limits
tests/                 unit and integration tests plus deterministic format fixtures
```

Add an analyzer through `AnalyzerAdapter`. Add a model host through a
`ProviderSpec`, transport client, and response normalization. The full component
map and trust boundaries are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```bash
./scripts/setup.sh
uv run pytest -q
uv run ruff check src tests
uv run ty check src/r2b/api.py src/r2b/bundle.py src/r2b/analysis/provenance.py
cd web/frontend && npm ci && npm test && npm run build
```

Start with [AGENTS.md](AGENTS.md) and [docs/USAGE.md](docs/USAGE.md).

## Responsible use and third-party software

r2brief's MIT license covers r2brief, not the target being analyzed. Before
using r2b, make sure you own the system, binary, firmware, or service or have
authorization to assess it. You are responsible for following applicable law,
contracts, organizational policy, and the licenses of the targets and tools you
use.

r2brief itself is MIT licensed. The MIT license includes the standard
no-warranty and limitation-of-liability terms; it does not grant rights to a
target, authorize access to somebody else's systems, or relicense third-party
software. r2b invokes optional tools and installs optional Python dependencies
under their own licenses. See [NOTICE.md](NOTICE.md) for the third-party map.
If you redistribute a container or appliance that includes third-party
binaries, review that artifact separately and include any notices or source
offers those licenses require.

Runtime adapters remain explicit because they execute or attach to a target.
Use an isolated environment and obtain authorization before enabling them.

MIT — [LICENSE](LICENSE). Third-party map: [NOTICE.md](NOTICE.md). r2brief is
not an official radare2 project.
