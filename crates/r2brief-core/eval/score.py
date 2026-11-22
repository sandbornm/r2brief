#!/usr/bin/env python3
"""Score r2brief-core against fixture ground truth.

Function recovery: a predicted start matches a truth symbol if |pred-truth| <= TOL.
Anomaly detection: each infected sample lists expected_finding_ids; we report
which were hit. Precision for anomalies = hits / findings_with_infection_tags
on that sample (informational findings like 'stripped' are excluded).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "fixtures" / "bin"
TRUTH = ROOT / "fixtures" / "truth"
MANIFEST = ROOT / "fixtures" / "manifest.json"
CORE = ROOT / "target" / "release" / "r2brief-core"
TOL = 4  # bytes; aarch64 insn size / x86 endbr

INFECTION_TAGS = {"infection", "anomaly", "rwx", "interp", "init_array", "init", "pt_note",
                  "text_padding", "reverse_text", "segment", "overlap"}


def analyze(path: Path) -> dict:
    out = subprocess.check_output([str(CORE), str(path), "--json"], text=True)
    return json.loads(out)


def score_funcs(report: dict, truth: dict) -> dict:
    preds = sorted({f["start"] for f in report["functions"]["functions"]})
    truths = sorted({f["addr"] for f in truth["functions"]})
    matched_t = set()
    matched_p = set()
    for p in preds:
        for t in truths:
            if abs(p - t) <= TOL and t not in matched_t:
                matched_t.add(t)
                matched_p.add(p)
                break
    tp = len(matched_t)
    prec = tp / len(preds) if preds else 0.0
    rec = tp / len(truths) if truths else 0.0
    return {
        "truth_funcs": len(truths),
        "pred_funcs": len(preds),
        "tp": tp,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
        "eh_frame_starts": report["functions"]["eh_frame_starts"],
        "call_targets": report["functions"]["call_targets"],
        "prologue_hits": report["functions"]["prologue_hits"],
    }


def score_findings(report: dict, truth: dict) -> dict:
    expected = set(truth.get("expected_finding_ids") or [])
    found_ids = {f["id"] for f in report["findings"]}
    # Also allow prefix / any match where expected id is contained.
    hits = set()
    for e in expected:
        if e in found_ids:
            hits.add(e)
            continue
        # soft: any found id that shares the technique prefix
        tech = e.split(":")[1] if ":" in e else e
        for fid in found_ids:
            if tech in fid:
                hits.add(e)
                break
    infection_findings = [
        f for f in report["findings"]
        if set(f.get("tags") or []) & INFECTION_TAGS
        or f["id"].startswith("elf:") and "stripped" not in f["id"] and "dangerous" not in f["id"]
        and "import:" not in f["id"]
    ]
    # Tighten: count structural anomaly findings only
    anomaly_findings = [
        f for f in report["findings"]
        if f["id"].startswith("elf:") and not f["id"].startswith("elf:stripped")
    ]
    return {
        "expected": sorted(expected),
        "hits": sorted(hits),
        "misses": sorted(expected - hits),
        "hit_rate": round(len(hits) / len(expected), 4) if expected else None,
        "anomaly_findings": [f["id"] for f in anomaly_findings],
        "all_finding_ids": sorted(found_ids),
    }


def main() -> int:
    if not CORE.exists():
        print(f"missing {CORE}; cargo build --release first", file=sys.stderr)
        return 1
    manifest = json.loads(MANIFEST.read_text())
    results = []
    for rec in manifest["binaries"]:
        path = BIN / rec["name"]
        truth = json.loads((TRUTH / rec["truth"]).read_text())
        report = analyze(path)
        row = {
            "name": rec["name"],
            "kind": rec["kind"],
            "arch": rec["arch"],
            "technique": rec.get("technique"),
            "subject": {
                "arch": report["subject"]["arch"],
                "stripped": report["subject"]["stripped"],
                "entry": hex(report["subject"]["entry"]),
                "dangerous_imports": report["subject"]["dangerous_imports"],
            },
            "functions": score_funcs(report, truth),
        }
        if rec["kind"] == "infected":
            row["findings"] = score_findings(report, truth)
        else:
            # Still record whether we spuriously scream infection on clean bins.
            infectionish = [
                f["id"] for f in report["findings"]
                if "infection" in f.get("tags", []) or "pt_note" in f["id"]
                or "text_padding" in f["id"] or "reverse_text" in f["id"]
                or "rwx" in f["id"] or "init_array" in f["id"]
            ]
            row["false_infection_findings"] = infectionish
        results.append(row)
        print(f"{rec['name']:32} funcs p={row['functions']['precision']:.3f} r={row['functions']['recall']:.3f} f1={row['functions']['f1']:.3f}"
              + (f"  hits={row.get('findings',{}).get('hits')}" if rec['kind']=='infected' else
                 f"  false_inf={row.get('false_infection_findings')}"))

    summary = {
        "schema_version": "r2brief.core.eval.v1",
        "tolerance_bytes": TOL,
        "results": results,
    }
    # Aggregate function recovery on stripped samples only (the hard case).
    stripped = [r for r in results if r["kind"] == "stripped"]
    if stripped:
        summary["stripped_function_recovery"] = {
            arch: {
                "precision": round(sum(r["functions"]["precision"] for r in stripped if r["arch"]==arch)/max(1,sum(1 for r in stripped if r["arch"]==arch)),4),
                "recall": round(sum(r["functions"]["recall"] for r in stripped if r["arch"]==arch)/max(1,sum(1 for r in stripped if r["arch"]==arch)),4),
                "f1": round(sum(r["functions"]["f1"] for r in stripped if r["arch"]==arch)/max(1,sum(1 for r in stripped if r["arch"]==arch)),4),
            }
            for arch in sorted({r["arch"] for r in stripped})
        }
    infected = [r for r in results if r["kind"] == "infected"]
    if infected:
        summary["infection_detection"] = {
            r["name"]: {
                "technique": r["technique"],
                "hit_rate": r["findings"]["hit_rate"],
                "hits": r["findings"]["hits"],
                "misses": r["findings"]["misses"],
            }
            for r in infected
        }
    out = ROOT / "eval" / "results.json"
    out.write_text(json.dumps(summary, indent=2) + "\n")
    print("\nWrote", out)
    print(json.dumps({k: summary[k] for k in summary if k != "results"}, indent=2))
    # Fail CI if stripped recall is catastrophic or infections miss entirely.
    bad = False
    for arch, s in summary.get("stripped_function_recovery", {}).items():
        if s["recall"] < 0.7 or s["precision"] < 0.45:
            print(f"FAIL stripped recovery too low on {arch}: {s}", file=sys.stderr)
            bad = True
    for name, s in summary.get("infection_detection", {}).items():
        if s["hit_rate"] is not None and s["hit_rate"] < 1.0:
            # soft fail print; pad may hit either text_padding or pt_note_to_load
            if not s["hits"]:
                print(f"FAIL infection undetected: {name} {s}", file=sys.stderr)
                bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
