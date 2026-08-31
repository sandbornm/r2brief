# Calibration samples

Calibration samples exercise triage behavior without pretending to be target
investigations. They are public, hash-pinned inputs selected to reveal noisy or
misleading output.

| Sample | Calibration purpose |
|---|---|
| [Debian GNU Hello, AArch64](hello-aarch64.md) | Known-benign negative control for import-only risk language and low-value startup handoffs |

The shared [fetch recipe](../../scripts/fetch_case_studies.sh) downloads and
extracts the package without running the target. Raw output is under
[`results/`](results/).
