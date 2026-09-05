# Specialist triage tools

r2b can collect Detect It Easy identification, capa capability matches, and
unblob extraction results alongside its usual analysis. These are optional host
CLIs; r2b does not install them into its Python environment or download rules
during analysis.

| Tool | Question it helps answer | r2b integration |
|---|---|---|
| Detect It Easy (`diec`) | What file type, compiler, packer, or protector does this resemble? | Optional quick-stage identification |
| Mandiant `capa` | Which capability rules match, and where is their evidence? | Optional deep-stage static analysis |
| `unblob` | What can be extracted from this container? | Existing bounded `--extract` path and artifact DAG |

## Install and enable

Install the upstream command-line tools appropriate to your host:

- [Detect It Easy releases](https://github.com/horsicq/Detect-It-Easy): install
  the console executable `diec` and its signature database, not only the GUI.
- [Mandiant capa installation](https://github.com/mandiant/capa/blob/master/doc/installation.md):
  standalone distributions include rules; a source installation may need a
  separate matching capa-rules checkout. The command must be Mandiant's `capa`.
- [unblob installation](https://unblob.org/installation/): install the CLI and
  required extraction helpers. r2b also requires bubblewrap for its default
  extraction sandbox.

Put executables on PATH, then check `r2b env --json`. Tool presence does not
guarantee that its rules, native libraries, or extraction helpers work; run
failures remain visible in the analysis.

Create `config/triage.local.toml` (or merge these keys into your existing local
overlay):

```toml
[analysis]
enable_die = true
enable_capa = true
die_timeout_s = 30
capa_timeout_s = 120
# Only if your capa installation needs external rules:
# capa_rules_path = "/absolute/path/to/capa-rules"
```

```bash
r2b brief ./sample.exe --config config/triage.local.toml --quick --json
r2b brief ./sample.exe --config config/triage.local.toml --deep --json
r2b brief ./firmware.bin --config config/triage.local.toml --quick --extract --json
```

DiE runs when enabled, including in quick mode. capa requires both
`enable_capa=true` and a deep pass; it is not scheduled on a top-level container.
Select an extracted executable and run a separate deep brief to use capa on it.
Both integrations default off. Neither runs the target natively or calls a model.

The first capa integration uses the CLI's default backend. Supported formats
and architectures depend on that backend and the installed version; do not
assume the default supports r2b's AArch64 targets. Unsupported format,
architecture, and OS exit codes produce a skip with the tool's reason.
Missing rules, invalid JSON, and timeouts produce failures. An empty successful
match set is a different result. Packed inputs can produce incomplete matches;
see [capa limitations](https://github.com/mandiant/capa/blob/master/doc/limitations.md).

## Evidence contract

`brief --json` adds a `triage_tools` object with status, warnings, counts, and
compact results. DiE signatures remain identification evidence. capa results
remain capability-rule matches, with the native address type retained. Neither
changes the fixed region scores or `handoff.next_argv`.

Full native JSON lives in `quick_scan.die.report` and `deep_scan.capa.report`
in the public analysis, persisted tool payloads, and bundles. Provenance hashes
the adapter payloads. A capa result's `report_ref` is a JSON pointer relative
to its native `report` object; `triage_tools.*.result_ref` points into the
companion public analysis. Summaries cap at 100 entries; `total` retains the
full count. The Markdown brief displays up to 12 entries per tool.

Reports larger than 16 MiB are rejected after execution. CLI stdout/stderr are
spooled to temporary files, with a timeout and bounded parsing. This is not an
OS sandbox or a hard temporary-disk quota. unblob continues to use the separate
extraction sandbox and its file, byte, depth, and time limits.

Unblob is invoked with `--report` and one worker. Its root chunk offsets are
read from TaskResult reports; nested offsets are not interpreted as root
offsets. Extracted files still feed the existing artifact inventory. The report
remains in extraction scratch storage; the DAG contains its normalized hits.

## A practical everyday kit

There is no universal kit for experienced reversers. A useful task-based split:

| Job | Tools to reach for |
|---|---|
| First contact | file/readelf, DiE, a hex viewer, strings |
| Capability and string leads | capa; FLOSS for supported obfuscated/compiler-specific strings |
| Code understanding | An established IDA, Binary Ninja, Ghidra, or radare2 workspace |
| Firmware contents | unblob/binwalk plus format-specific filesystem tools |
| Observed behavior | A debugger, tracing, or an isolated runtime appropriate to the target |
| Carrying work forward | Saved analysis databases, scripts, and r2b records/bundles |

FLOSS, DiE, and capa have different platform coverage. r2b currently wraps DiE
and capa as described above; this table does not imply a FLOSS adapter or IDA/
Binary Ninja integration. Start with the tool that answers the current question.
