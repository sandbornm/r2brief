# Limits and fit

r2brief is strongest as a first-pass triage and handoff layer. It is not a
replacement for a disassembler, emulator, debugger, format-specific runtime
tool, or an analyst who already has a scoped question.

## Good fit

- unfamiliar ELF, PE, Mach-O, firmware, container, or raw-blob inputs;
- repeatable baselines across a corpus or uneven lab machines;
- choosing a few addresses/artifacts before opening a heavier tool;
- analyst-to-agent handoffs that need structured stdout and exact argv;
- recording tool availability, failure, evidence, and SHA identity.

## Weak fit without more scope

- large C++ runtimes, browsers, kernels, office suites, or game engines;
- statically linked monoliths with thousands of imports/symbols;
- generated/JIT code that does not exist in the file being inspected;
- packed/obfuscated targets without an unpacking or runtime strategy;
- questions that depend on runtime state, timing, environment, or IPC;
- a target already understood and open at the right function in r2/Ghidra.

For code objects at least 32 MiB, 1,000 imports, or 5,000 discovered functions,
the briefing marks `subject.triage_scope` as `broad`, changes aggregate
`risk_level` to `unscored`, records `scope_warnings`, and sets
`handoff.requires_scope=true`. Automatic `next_argv` is suppressed until the
caller supplies a useful scope such as a dependency, crash address, export,
subsystem, or version diff. The threshold is a warning boundary, not a claim
that smaller files are safe or larger files are unanalyzable.

## V8 / Node stress test

The current Apple Silicon development host provided a concrete failure case:

| Input | Size | Quick wall time | Result |
|---|---:|---:|---|
| Homebrew Node launcher | 67 KiB | 2.6 s | 1 entry region; V8 lived elsewhere |
| `libnode.141.dylib` | 65 MiB | 29.9 s | 1,930 imports; 6 generic regions; `broad/unscored` |

The launcher imports `libnode`, so analyzing only the executable does not load
the engine. The current orchestrator does not recursively analyze linked shared
libraries for ELF/Mach-O/PE code subjects; pass the owning object explicitly.

For a useful V8 investigation:

1. Start from a concrete scope: crash PC, exported API, subsystem, patch diff,
   snapshot, builtin, or named namespace.
2. Analyze the owning executable/shared object rather than assuming the launcher
   contains the implementation.
3. Use symbols, dSYM/PDB, link maps, relocations, sections, and call-graph
   clustering when present. A final stripped binary cannot reliably recreate
   original `.o` boundaries; supply archives/object files when you have them.
4. Add a V8-specific adapter for snapshot/builtin metadata if that is the
   question. Generic strings and dangerous-import counts have poor precision in
   a runtime of this size.
5. Capture generated/JIT code at runtime with the appropriate debugger,
   instrumentation, emulator, or V8 tooling. Static triage cannot inspect bytes
   that have not been generated yet.

## Size and resource limits

- Web uploads: 200 MB by default (`analysis.max_binary_size`). This is a web
  ingress cap, not a CLI/library cap.
- CLI/library input: no hard file-size limit; runtime and memory depend on the
  selected host tools. Large targets receive the broad-scope warning above.
- Extraction defaults: 64 MiB total output, 200 files, depth 2, 60 seconds.
- Firmware upload/extraction is deliberately bounded; truncated inventory and
  tool skips are reported.
- Ghidra and dynamic adapters have their own subprocess/runtime limits. The
  orchestrator no longer exposes generic quick/deep timeout settings because
  they did not safely terminate adapter processes.
- `--quick` entry snippets are r2 `pdf` after `af` at the entry VA, not an
  unanalyzed `pD` of N bytes (that can end on a torn `invalid` opcode).

## What scores mean

Region scores are deterministic ordering points, not probabilities, severity,
or proof of vulnerability. High-cardinality runtimes create base-rate noise:
common memory, process, network, and loader APIs are expected there. Read the
region `why`, source, address, and snippet; discard the ordering when the stated
reason does not match the investigation goal.
