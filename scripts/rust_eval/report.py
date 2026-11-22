#!/usr/bin/env python3
"""Render eval_ground_truth.py results as Markdown and apply the soft floor.

A binary fails when its user-code p@5 drops more than one hit (0.2) below
baseline, its p@10 drops more than one hit (0.1) below baseline, or r2b did
not produce a briefing. Scores above baseline never fail.

usage: report.py <results.json> <baseline.json> [--summary PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TOLERANCE = {"p@5": 0.2, "p@10": 0.1}
EPS = 1e-9


def check(row: dict, base: dict | None, mode: str = "quick") -> list[str]:
    res = row[mode]
    problems = []
    if res.get("error"):
        problems.append(f"r2b error: {res['error'][-200:]}")
    if base:
        for k, tol in TOLERANCE.items():
            if res[k] < base[k] - tol - EPS:
                problems.append(f"{k} {res[k]:.2f} < baseline {base[k]:.2f} - {tol}")
    return problems


def render(rows: list[dict], baseline: dict, mode: str = "quick") -> tuple[str, bool]:
    lines = [
        "## Stripped Rust eval: fd-find 10.5.2, aarch64",
        "",
        f"`r2b brief --{mode}` user-code precision against symbol ground truth from the "
        "unstripped twin. Soft floor: fails only on a drop of more than one hit below baseline.",
        "",
        "| binary | p@5 | p@10 | baseline p@5/p@10 | first user rank | `fd::main` rank "
        "| user fns | ranked | secs | status |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    failed = False
    details = []
    for row in rows:
        res, base = row[mode], baseline.get(row["binary"])
        problems = check(row, base, mode)
        failed |= bool(problems)
        status = "fail: " + "; ".join(problems) if problems else "ok"
        base_cell = f"{base['p@5']:.2f}/{base['p@10']:.2f}" if base else "none"
        lines.append(
            f"| `{row['binary']}` | {res['p@5']:.2f} | {res['p@10']:.2f} | {base_cell} "
            f"| {res['first_user_rank'] or '-'} | {res['user_main_rank'] or '-'} "
            f"| {res['user_total']} of {row['n_funcs']} | {res['n_ranked']} | {res['secs']} "
            f"| {status} |"
        )
        top = "\n".join(f"{i + 1}. `{a}` {k or '?'}: `{n}`" for i, (a, n, k) in
                        enumerate(res.get("top") or []))
        details.append(f"<details><summary>Top 10 for {row['binary']}</summary>\n\n{top}\n\n"
                       "</details>")
    return "\n".join(lines + [""] + details) + "\n", failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args(argv)
    rows = json.loads(args.results.read_text())
    baseline = json.loads(args.baseline.read_text())
    text, failed = render(rows, baseline)
    print(text)
    if args.summary:
        with args.summary.open("a") as fh:
            fh.write(text)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
