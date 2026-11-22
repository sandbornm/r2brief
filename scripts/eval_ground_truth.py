#!/usr/bin/env python3
"""Score `r2b brief` region addresses against per-function ground truth.

Offline measurement helper. It shells out to an `r2b` executable and never
calls a model. Ground truth layout (one JSON object per line):

    <data-root>/dataset/truth/<target>/<profile>/<crate>.jsonl
    fields used: addr, size, name, kind ("user" counts as relevant)

Binaries are given relative to <data-root>, e.g.
`out/bins/aarch64-unknown-linux-gnu/release-strip/ac_cli`.

Metrics per mode (quick, deep): precision@1/3/5/10 over ranked region
addresses mapped to their containing true function, rank of the first user
function, and rank of the user entry function (`<crate>::main` or
`<crate>::__cortex_m_rt_main`).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

KS = (1, 3, 5, 10)


def load_truth(root: Path, binary: str) -> list[dict]:
    target, profile, crate = binary.split("/")[-3:]
    path = root / "dataset" / "truth" / target / profile / f"{crate}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def containing(recs: list[dict], addr: int) -> dict | None:
    for rec in recs:
        start = rec["addr"]
        if start <= addr < start + max(rec["size"], 1):
            return rec
        if rec.get("thumb") and start <= (addr & ~1) < start + max(rec["size"], 1):
            return rec
    return None


def ranked_addrs(brief: dict) -> list[int]:
    out: list[int] = []
    handoff = brief.get("handoff") or {}
    for region in handoff.get("regions") or brief.get("regions") or []:
        raw = region.get("addr")
        if raw in (None, ""):
            continue
        try:
            value = int(raw, 16) if isinstance(raw, str) else int(raw)
        except ValueError:
            continue
        if value not in out:
            out.append(value)
    for raw in handoff.get("decompile_addrs") or []:
        if raw in (None, ""):
            continue
        try:
            value = int(raw, 16) if isinstance(raw, str) else int(raw)
        except (TypeError, ValueError):
            continue
        if value not in out:
            out.append(value)
    return out


def is_entry(rec: dict | None, crate: str) -> bool:
    if not rec or rec.get("kind") != "user":
        return False
    return rec["name"] in (f"{crate}::main", f"{crate}::__cortex_m_rt_main")


def metrics(ranked: list[int], recs: list[dict], crate: str) -> dict:
    mapped = [containing(recs, a) for a in ranked]
    # Count each true function once so repeated regions in one function do not inflate precision.
    seen: set[int] = set()
    hits: list[bool] = []
    for rec in mapped:
        if rec is not None and rec["addr"] in seen:
            hits.append(False)
            continue
        if rec is not None:
            seen.add(rec["addr"])
        hits.append(bool(rec and rec.get("kind") == "user"))
    first = next((i + 1 for i, hit in enumerate(hits) if hit), None)
    entry = next((i + 1 for i, rec in enumerate(mapped) if is_entry(rec, crate)), None)
    result = {
        "n_ranked": len(ranked),
        "first_user_rank": first,
        "user_main_rank": entry,
        "user_total": sum(r.get("kind") == "user" for r in recs),
        "user_found": len({r["addr"] for r in mapped if r and r.get("kind") == "user"}),
    }
    for k in KS:
        denom = min(k, len(hits))
        result[f"p@{k}"] = round(sum(hits[:k]) / denom, 3) if denom else 0.0
    result["top"] = [
        [hex(a), (r["name"][:80] if r else None), (r.get("kind") if r else None)]
        for a, r in zip(ranked[:10], mapped[:10])
    ]
    return result


def run_brief(
    r2b: str, binary: Path, mode: str, max_regions: int, nice: int
) -> tuple[dict | None, float, str | None]:
    argv = [
        r2b,
        "brief",
        str(binary),
        f"--{mode}",
        "--max-regions",
        str(max_regions),
        "--no-save",
        "--json",
    ]
    if nice:
        argv = ["nice", "-n", str(nice), *argv]
    started = time.time()
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    elapsed = round(time.time() - started, 1)
    try:
        return json.loads(proc.stdout), elapsed, None
    except json.JSONDecodeError:
        return None, elapsed, proc.stderr[-500:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--r2b", default="r2b", help="r2b executable to measure")
    parser.add_argument("--modes", default="quick,deep")
    parser.add_argument("--max-regions", type=int, default=20)
    parser.add_argument("--nice", type=int, default=19)
    parser.add_argument("--out", type=Path, help="write full JSON results here")
    parser.add_argument("binaries", nargs="+")
    args = parser.parse_args(argv)

    rows = []
    for binary in args.binaries:
        recs = load_truth(args.data_root, binary)
        crate = binary.split("/")[-1]
        row: dict = {"binary": binary, "n_funcs": len(recs)}
        for mode in args.modes.split(","):
            brief, secs, err = run_brief(
                args.r2b, args.data_root / binary, mode, args.max_regions, args.nice
            )
            if brief is None and not err:
                err = "r2b did not emit JSON"
            row[mode] = {
                "secs": secs,
                "error": err,
                **metrics(ranked_addrs(brief or {}), recs, crate),
            }
            if brief:
                row[mode]["rust"] = brief.get("rust")
        rows.append(row)
        brief_line = {
            m: {
                k: row[m][k]
                for k in ("secs", "first_user_rank", "user_main_rank", "p@1", "p@3", "p@5", "p@10")
            }
            for m in args.modes.split(",")
        }
        print(json.dumps({"binary": binary, **brief_line}), flush=True)
    if args.out:
        args.out.write_text(json.dumps(rows, indent=1))
    failed = any(row[m].get("error") for row in rows for m in args.modes.split(","))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
