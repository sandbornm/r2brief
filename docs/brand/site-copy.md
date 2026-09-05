# Homepage copy draft

Editorial draft for r2brief-site. Not applied to the website or deployed.
Keep the existing colors, typography, cards, and visual treatments.

## Navigation

Use cases · How it works · Examples · Install · GitHub

## Hero

Eyebrow: For unfamiliar executables and firmware

Headline: Get your bearings. Keep the evidence.

Body: r2brief brings together binary analysis tools into a compact brief:
what a file contains, places to inspect, and what the tools could—and could
not—analyze. Follow a lead and keep the results in a shareable record.

Primary action: Run your first brief

Secondary action: See an example

Supporting note: Most tested on AArch64 ELF and selected firmware samples.
Default analysis runs locally without executing the target or calling a model.

## Use cases

### Start with an unfamiliar executable

Check its format, architecture, imports, and analysis coverage. Get a short
list of inspection leads with supporting facts.

### Look inside firmware

Inventory embedded artifacts and use bounded extraction to select files for
deeper inspection. Keep their hashes and relationships with the analysis.

### Follow up on a lead

Locate callers of a selected import or request a focused decompile. Keep
identification clues separate from conclusions supported by code or runtime
evidence.

### Share the analysis around your project

Export a compact brief with tool results, coverage, and provenance in a portable
bundle. Your Ghidra project remains the workspace for detailed code analysis.

### Give your RE agents a structured starting point

Give your agent a compact brief of an unfamiliar binary, with inspection
leads, supporting evidence, and analysis coverage. Agents can request follow-up
analysis through r2b's CLI and read saved results in a later session.

## How it works

1. **Brief a file.** Identify the subject and collect evidence using the
   available tools.
2. **Inspect a lead.** Choose a follow-up question and examine the relevant
   caller or function.
3. **Keep the results.** Save the analysis or export a bundle for another
   person or program to inspect.

## Worked example

Title: From firmware contents to a focused code inspection

Body: In a recorded OpenWrt investigation, file hashes narrowed a release
comparison and follow-up analysis examined a changed routine. Explore the
saved evidence, tool coverage, and limits of the run.

Link: Explore the OpenWrt example

Editorial placement: Keep the interactive graph here, below the product
explanation. The release comparison is one use case. Retain the full case's
limitations and distinction between the published advisory and r2b's contribution.

## Additional examples

Use compact links to the agent experiment and calibration pages. Keep benchmark
counts, raw addresses, schema-field explanations, decompiler handoff failures,
and model comparisons on those pages. Each linked page should start with the
question, outcome, and limitation in plain language.

## Install

Title: Run your first brief

```bash
git clone https://github.com/sandbornm/r2brief.git
cd r2brief
./scripts/install.sh
source .venv/bin/activate
r2b brief ./sample.bin --quick
```

Supporting links: Install options · CLI and Python usage · Optional triage tools

Editorial placement: Put flavor details and JSON/harness examples below this
first-run path. Link to optional DiE/capa/unblob setup without suggesting those
tools are included in every installation.

## Metadata

Title: r2brief — Binary triage and portable evidence

Description: Get oriented in unfamiliar executables and firmware. Collect
inspection leads, analysis coverage, and supporting tool results in a compact
brief for you and your RE agents.
