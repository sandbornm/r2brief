# What the quick pass does on the bundled fixtures

The bundled programs are small teaching binaries. They are useful for checking
format handling, architecture handling, and rank policy. They are not target
investigations, and most of them should not produce a security lead.

The table below records the current `triage` profile. The checks run the same
public `analyze()` path used by `r2b brief --quick`; they do not execute a
sample or call a model.

| Sample | First-pass result | Honest reading |
|---|---|---|
| ARM32 `sample.bin` | `Entry / main` | Format and calling-convention baseline. There is no sink lead to follow. |
| AArch64 `crypto_simple` | `Entry / main` | The quick pass does not infer XOR, ROT13, or hashing from code shape. Use a named function or a deeper pass if that is the question. |
| AArch64 `fibonacci` | `Entry / main` | The entry listing contains a call to `fibonacci`, but the quick ranker does not claim to recognize recursion. |
| AArch64 `hello` | `Entry / main` | Benign control. Stopping at the entry is better than inventing a finding. |
| AArch64 `structs` | `Entry / main` | The import inventory includes allocation calls, but the quick pass does not recover structure layouts. |
| AArch64 `syscalls` | `Entry / _start`; zero imports | Direct syscalls are outside the import-led quick heuristic. This sample keeps that limit visible. |
| AArch64 `vulnerable` | `Entry / main`, then `strcpy` import | A useful lead, not proof of overflow. The caller and destination size still need checking. |
| Native `shallow-host` | entry, then fortified `__strcpy_chk` import | Confirms Mach-O intake and platform-specific import spelling. |
| AArch64 `shallow-linux-arm64` | `Entry / main`, then `strcpy` import | Exercises the intended brief → verify → one-function decompile loop. |

The important split is simple: the quick pass is useful when cheap evidence
narrows the next question. On the algorithm and data-layout examples, it mostly
provides identity and an entry listing. That is a limit, not a failed security
finding.

## Re-run the contract

The expected region order and dangerous-import set are stored in
[`samples/first-pass-expectations.json`](../../samples/first-pass-expectations.json).
The integration check runs every committed sample through the real adapter
stack when radare2 is installed:

```bash
uv run pytest -q tests/integration/test_sample_briefs.py
```

The manifest coverage test runs without external analysis tools:

```bash
uv run pytest -q tests/unit/test_triage_samples.py
```
