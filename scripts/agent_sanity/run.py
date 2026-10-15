#!/usr/bin/env python3
"""Opt-in cross-agent sanity harness (never CI-default).

Runs the fixed r2brief skill prompt against each available CLI agent
(codex / claude / grok) with only r2b-exec intended. Scores transcripts
against tests/goldens/*/expected.json. Missing CLIs are reported, not failures.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import score_run

AGENTS = ("codex", "claude", "grok")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def discover_agents() -> dict[str, dict]:
    found: dict[str, dict] = {}
    for name in AGENTS:
        path = shutil.which(name)
        found[name] = {
            "installed": path is not None,
            "path": path,
            "logged_in": None,
            "status": "missing" if path is None else "present",
        }
        if path is None:
            continue
        # Best-effort login probes; never fail the harness on probe errors.
        try:
            if name == "codex":
                # auth.json presence or successful version is enough for "available"
                auth = Path.home() / ".codex" / "auth.json"
                found[name]["logged_in"] = auth.is_file()
            elif name == "claude":
                proc = subprocess.run(
                    [path, "auth", "status"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                blob = proc.stdout + proc.stderr
                found[name]["logged_in"] = '"loggedIn": true' in blob
            
            elif name == "grok":
                auth = Path.home() / ".grok" / "auth.json"
                found[name]["logged_in"] = auth.is_file() or (Path.home() / ".grok").is_dir()
            if found[name]["logged_in"] is False:
                found[name]["status"] = "installed_not_logged_in"
            elif found[name]["logged_in"]:
                found[name]["status"] = "ready"
            else:
                found[name]["status"] = "present_login_unknown"
        except (OSError, subprocess.SubprocessError) as exc:
            found[name]["status"] = f"probe_error:{exc}"
    return found


def ensure_r2b_exec_on_path(root: Path, bindir: Path) -> Path:
    bindir.mkdir(parents=True, exist_ok=True)
    wrapper = bindir / "r2b-exec"
    # Prefer installed console script via uv run; fall back to module.
    wrapper.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'cd "{root}"\n'
        'if command -v uv >/dev/null 2>&1; then\n'
        '  exec uv run --no-sync r2b-exec "$@"\n'
        'fi\n'
        f'export PYTHONPATH="{root}/src${{PYTHONPATH:+:$PYTHONPATH}}"\n'
        'exec python3 -m r2b.harness.exec_shim "$@"\n'
    )
    wrapper.chmod(0o755)
    return wrapper


def build_prompt(golden_id: str, golden_dir: Path, expected: dict) -> str:
    skill = (repo_root() / "docs" / "skills" / "r2brief.md").read_text(encoding="utf-8")
    score = expected.get("agent_score") or {}
    return f"""You are running an r2brief agent-sanity evaluation.

HARD RULES:
- You may only invoke analysis tools via the `r2b-exec` command on PATH.
- Do not call a model through r2b (no --ask, no --mode llm/both, no --review-lens).
- Do not execute target binaries.
- Stay inside this golden directory: {golden_dir}
- Follow the skill loop below.

SKILL:
{skill}

CASE id={golden_id}
{expected.get('case')}

Working directory: {golden_dir}

What to do:
1) Use only r2b-exec against the files in this directory (see expected.json for hints).
2) For openwrt_ubusd: run `r2b-exec diff tree_a tree_b --json --paths` and report the three changed ELF paths.
3) For asus_cve_2024_3079 / totolink_cwe78: run verify with --tags-file TAGS.md against ../hello/hello and report tags + the named sink/import from the case.
4) For hello: run brief/verify with tags as needed.

Finish with a single JSON object on stdout (and nothing else after it) with keys:
{{"golden_id","changed_files","sink","import","tags","commands"}}
changed_files should list relpaths when relevant. tags should include cwe/tid.
Scoring looks for: {json.dumps(score)}
"""


def run_agent(agent: str, path: str, prompt: str, cwd: Path, timeout: int) -> dict:
    env = os.environ.copy()
    start = time.time()
    if agent == "codex":
        cmd = [
            path,
            "exec",
            "--sandbox",
            "workspace-write",
            "-C",
            str(cwd),
            "--json",
            prompt,
        ]
    elif agent == "claude":
        cmd = [
            path,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--allowedTools",
            "Bash",
            "--add-dir",
            str(cwd),
        ]
    elif agent == "grok":
        cmd = [
            path,
            "--prompt",
            prompt,
            "--cwd",
            str(cwd),
            "--output-format",
            "json",
            "--always-approve",
        ]
    else:
        raise ValueError(agent)
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd),
            env=env,
        )
        elapsed = time.time() - start
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "elapsed_s": elapsed,
            "cmd": cmd[:6],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": f"timeout after {timeout}s",
            "elapsed_s": float(timeout),
            "cmd": cmd[:6],
        }


def extract_final_json(text: str) -> dict | None:
    if not text:
        return None
    # Prefer last JSON object in the blob.
    matches = list(re.finditer(r"\{[\s\S]*\}", text))
    for match in reversed(matches):
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
    return None



def markdown_table(rows: list[dict]) -> str:
    lines = [
        "| host | agent | status | golden | passed | notes |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        notes = "; ".join(row.get("notes") or []) or row.get("detail", "")
        lines.append(
            "| {host} | {agent} | {status} | {golden} | {passed} | {notes} |".format(
                host=row.get("host", ""),
                agent=row.get("agent", ""),
                status=row.get("status", ""),
                golden=row.get("golden", "-"),
                passed=row.get("passed", "-"),
                notes=notes.replace("|", "/"),
            )
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument(
        "--goldens",
        nargs="*",
        default=["openwrt_ubusd", "asus_cve_2024_3079", "totolink_cwe78", "hello"],
    )
    parser.add_argument("--agents", nargs="*", default=list(AGENTS))
    parser.add_argument("--dry-discover", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    out_dir = args.out or (root / "scripts" / "agent_sanity" / "results")
    out_dir.mkdir(parents=True, exist_ok=True)

    host = os.uname().nodename
    agents = discover_agents()
    if args.dry_discover:
        print(json.dumps({"host": host, "agents": agents}, indent=2))
        return 0

    bindir = out_dir / "bin"
    ensure_r2b_exec_on_path(root, bindir)
    os.environ["PATH"] = str(bindir) + os.pathsep + os.environ.get("PATH", "")

    rows: list[dict] = []
    results: dict = {"host": host, "agents": agents, "runs": []}

    for agent_name in args.agents:
        info = agents.get(agent_name) or {"installed": False, "status": "missing"}
        if not info.get("installed"):
            rows.append(
                {
                    "host": host,
                    "agent": agent_name,
                    "status": "missing",
                    "golden": "-",
                    "passed": "-",
                    "notes": ["CLI not installed"],
                }
            )
            continue
        if info.get("status") == "installed_not_logged_in":
            rows.append(
                {
                    "host": host,
                    "agent": agent_name,
                    "status": "installed_not_logged_in",
                    "golden": "-",
                    "passed": "-",
                    "notes": ["installed but not logged in"],
                }
            )
            continue

        for golden_id in args.goldens:
            gdir = root / "tests" / "goldens" / golden_id
            expected = json.loads((gdir / "expected.json").read_text(encoding="utf-8"))
            if "agent_score" not in expected and golden_id != "hello":
                continue
            if golden_id == "hello" and "agent_score" not in expected:
                # light hello agent score
                expected = {
                    **expected,
                    "agent_score": {
                        "allowlist_only": True,
                        "no_r2b_model": True,
                        "max_steps": 10,
                        "max_seconds": args.timeout,
                    },
                }
            prompt = build_prompt(golden_id, gdir, expected)
            run = run_agent(agent_name, info["path"], prompt, gdir, args.timeout)
            transcript = (run.get("stdout") or "") + "\n" + (run.get("stderr") or "")
            final = extract_final_json(run.get("stdout") or "")
            scored = score_run(
                golden=expected,
                transcript=transcript,
                final_answer=final,
                elapsed_s=float(run.get("elapsed_s") or 0),
            )
            entry = {
                "host": host,
                "agent": agent_name,
                "status": info.get("status"),
                "golden": golden_id,
                "passed": scored["passed"],
                "checks": scored["checks"],
                "notes": scored["notes"],
                "elapsed_s": scored["elapsed_s"],
                "returncode": run.get("returncode"),
            }
            results["runs"].append(entry)
            rows.append(
                {
                    **entry,
                    "detail": f"rc={run.get('returncode')} steps={scored['step_count']}",
                }
            )
            (out_dir / f"{host}-{agent_name}-{golden_id}.transcript.txt").write_text(
                transcript, encoding="utf-8"
            )

    results_path = out_dir / f"results-{host}.json"
    md_path = out_dir / f"results-{host}.md"
    results_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown_table(rows), encoding="utf-8")
    print(md_path.read_text(encoding="utf-8"))
    print(f"wrote {results_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
