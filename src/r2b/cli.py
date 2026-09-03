"""Typer-based CLI (binary: r2b; library: r2b)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.table import Table

from .analysis.briefing import build_briefing, build_handoff, render_briefing_markdown
from .analysis.handoff import publish_analysis_session
from .analysis.insights import extract_insights, save_lab_note
from .analysis.record import AnalysisRecordStore
from .analysis.review import (
    MAX_REVIEW_WIDTH,
    ReviewError,
    normalize_review_mode,
    review_briefing,
    review_briefing_set,
)
from .analysis.result_dto import analysis_result_to_public_dict
from .bundle import (
    BundleError,
    create_bundle as create_evidence_bundle,
    default_bundle_path,
    inspect_bundle as inspect_evidence_bundle,
    read_bundle as read_evidence_bundle,
)
from .config import USER_CONFIG_PATH, load_config
from .environment import EnvironmentReport, detect_environment
from .environment.setup import recommend_setup
from .environment.ghidra import detect_ghidra
from .environment.ghidra_setup import GhidraSetupError, GhidraSetupResult, setup_ghidra
from .llm import ChatMessage as LLMChatMessage, LLMBridge, LLMError
from .llm.citations import parse_cited_claims
from .llm.prompts import ANALYST_SYSTEM
from .state import AppState, build_state
from .pilot import (
    build_engine,
    enqueue as pilot_enqueue,
    pilot_dir_for,
    report_text as pilot_report_text,
    status as pilot_status,
    step_log as pilot_step_log,
    watch as pilot_watch,
)
from .utils.serialization import to_json
from .paths import find_checkout_root, shipped_config_dir
from . import __version__

app = typer.Typer(add_completion=False, no_args_is_help=True)
ghidra_app = typer.Typer(help="Inspect or install a local Ghidra distribution.", add_completion=False)
records_app = typer.Typer(help="List or reopen tagged per-binary analysis records.", add_completion=False)
bundle_app = typer.Typer(help="Create or inspect portable evidence bundles.", add_completion=False)
pilot_app = typer.Typer(
    help="Experimental in-process planner. Prefer an external harness (omp / Claude Code).",
    add_completion=False,
    hidden=True,
)
app.add_typer(ghidra_app, name="ghidra")
app.add_typer(records_app, name="records")
app.add_typer(bundle_app, name="bundle")
app.add_typer(pilot_app, name="pilot", hidden=True)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        sys.stdout.write(__version__ + "\n")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print the installed version and exit.",
    ),
) -> None:
    """Ranked regions, SHA-256 records, optional LLM asks.

    Planners: `r2b brief BIN --quick --json`.
    """
    _ = version


def _emit_json(payload: Any) -> None:
    """Write JSON to stdout without Rich wrapping or ANSI."""
    sys.stdout.write(to_json(payload) + "\n")


def _require_binary(binary: Path) -> None:
    if not binary.exists():
        err_console.print(f"[red]Binary path does not exist: {binary}")
        raise typer.Exit(code=1)


@app.command(hidden=True)
def analyze(
    binary: Path = typer.Argument(..., help="Path to ELF or supported binary"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    quick: bool = typer.Option(False, "--quick", help="Quick scan only"),
    skip_deep: bool = typer.Option(False, "--skip-deep", help="Skip deep analysis stage"),
    json_output: bool = typer.Option(False, "--json", help="Emit briefing JSON (same shape as `brief --json`)"),
    brief: bool = typer.Option(False, "--brief", help="Print ranked region briefing instead of the full dump"),
    ask: Optional[str] = typer.Option(None, "--ask", help="Question to ask LLM about the briefing"),
    ask_regions: int = typer.Option(0, "--ask-regions", help="Send the first N region asks to the LLM"),
    tags: Optional[list[str]] = typer.Option(None, "--tag", help="Extra record tags. Repeatable."),
    extract: bool = typer.Option(
        False, "--extract", help="Run sandboxed binwalk3/unblob and merge into the artifact DAG"
    ),
    no_save: bool = typer.Option(
        False, "--no-save", help="Do not create records, sessions, or trajectory rows"
    ),
) -> None:
    """Full adapter dump. Planners should use `brief --json`."""

    _require_binary(binary)

    state: AppState = build_state(config_path, persist=not no_save)
    if extract:
        state.config.extract.enable = True

    plan = state.orchestrator.create_plan(quick_only=quick, skip_deep=skip_deep)
    result = state.orchestrator.analyze(binary, plan)
    record = None if no_save else _persist_record(state, result, binary, extra_tags=tags)
    public = analysis_result_to_public_dict(result, record=record)
    session = None if no_save else _publish_session(state, result, public)
    if session:
        public["session_id"] = session.session_id
    record_id = (record or {}).get("record_id") if record else None
    briefing = public.get("briefing") or build_briefing(public, record_id=record_id)
    briefing["handoff"] = build_handoff(briefing, record_id=record_id)
    public["briefing"] = briefing
    answered, ask_payload = True, None
    if not json_output:
        if brief:
            console.print(render_briefing_markdown(briefing))
        else:
            _render_result(result)
            if record:
                console.print(
                    f"[cyan]Record[/] {record.get('record_id')}  rev {record.get('revision')}  {record.get('directory')}"
                )
            console.print(render_briefing_markdown(briefing, include_asks=False))
    if ask or ask_regions:
        answered, ask_payload = _ask_briefing(
            state,
            briefing,
            question=ask,
            region_count=ask_regions,
            out=err_console if json_output else console,
        )
        if ask_payload:
            briefing["ask_result"] = ask_payload
            public["briefing"] = briefing
    if json_output:
        _emit_json(briefing)
        if not answered:
            raise typer.Exit(code=2)


@app.command()
def brief(
    binary: Path = typer.Argument(..., help="Path to ELF, firmware blob, or carved child"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    quick: bool = typer.Option(
        True,
        "--quick/--deep",
        help="Run the default triage scan; --deep enables the regular deep stage",
    ),
    skip_deep: bool = typer.Option(False, "--skip-deep", help="Skip deep analysis stage"),
    json_output: bool = typer.Option(False, "--json", help="Emit briefing JSON"),
    ask: bool = typer.Option(False, "--ask", help="Send the overall briefing ask to the LLM"),
    ask_regions: int = typer.Option(0, "--ask-regions", help="Send the first N region asks to the LLM"),
    max_regions: int = typer.Option(6, "--max-regions", help="Cap ranked regions"),
    tags: Optional[list[str]] = typer.Option(None, "--tag", help="Extra record tags. Repeatable."),
    verify: bool = typer.Option(False, "--verify", help="Resolve dangerous-import arguments before printing"),
    extract: bool = typer.Option(
        False, "--extract", help="Run sandboxed binwalk3/unblob and merge into the artifact DAG"
    ),
    no_save: bool = typer.Option(
        False, "--no-save", help="Do not create records, sessions, or trajectory rows"
    ),
) -> None:
    """Break a binary into ranked regions and emit Qwen-sized snippet asks."""

    _require_binary(binary)

    state: AppState = build_state(config_path, persist=not no_save)
    if extract:
        state.config.extract.enable = True
    plan = state.orchestrator.create_plan(quick_only=quick, skip_deep=skip_deep)
    result = state.orchestrator.analyze(binary, plan)
    record = None if no_save else _persist_record(state, result, binary, extra_tags=tags)
    public = analysis_result_to_public_dict(result, record=record)
    session = None if no_save else _publish_session(state, result, public)
    record_id = (record or {}).get("record_id") if record else None
    briefing = build_briefing(result, max_regions=max_regions, record_id=record_id)
    if verify:
        from .adapters.radare2 import Radare2Adapter
        from .analysis.verify import DEFAULT_IMPORTS, collect_verify_names

        dangerous = list((briefing.get("subject") or {}).get("dangerous_imports") or [])
        names = collect_verify_names(dangerous) or list(DEFAULT_IMPORTS)
        briefing["verified_imports"] = Radare2Adapter().verify_scan(binary, names)
        briefing["handoff"] = build_handoff(briefing, record_id=record_id)
    meta = err_console if json_output else console
    if record:
        meta.print(f"[cyan]Record[/] {record.get('record_id')}  rev {record.get('revision')}  {record.get('directory')}")
    if session:
        meta.print(f"[cyan]Session[/] {session.session_id}")

    answered, ask_payload = True, None
    if not json_output:
        console.print(render_briefing_markdown(briefing))
    if ask or ask_regions:
        answered, ask_payload = _ask_briefing(
            state,
            briefing,
            question=briefing.get("overall_ask") if ask else None,
            region_count=ask_regions,
            out=meta,
        )
        if ask_payload:
            briefing["ask_result"] = ask_payload
    if json_output:
        _emit_json(briefing)
        if not answered:
            raise typer.Exit(code=2)


@app.command()
def review(
    briefing_path: Path = typer.Argument(
        ...,
        help="Path to r2b.briefing.v1 JSON, public analysis JSON, or an .r2br bundle",
    ),
    mode: str = typer.Option(
        "rules",
        "--mode",
        help="Review mode: rules, llm, both (compare is an alias for both)",
    ),
    thesis: Optional[str] = typer.Option(
        None,
        "--thesis",
        help="Question or audit thesis for the independent model ordering",
    ),
    width: Optional[int] = typer.Option(
        None,
        "--width",
        min=1,
        max=MAX_REVIEW_WIDTH,
        help="Independent lens count; emits r2b.review-set.v1 when set",
    ),
    lenses: Optional[list[str]] = typer.Option(
        None,
        "--lens",
        help="Custom lens thesis; repeatable and applied before built-in lenses",
    ),
    top_k: int = typer.Option(
        2,
        "--top",
        min=1,
        help="Regions from each pass included in the width overlay",
    ),
    config_path: Optional[Path] = typer.Option(
        None,
        "--config",
        help="LLM overlay TOML; ignored by rules mode",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit versioned review JSON"),
) -> None:
    """Screen evidence maturity and optionally compare a model order."""

    try:
        selected_mode = normalize_review_mode(mode)
        briefing = _load_review_briefing(briefing_path)
        if width is not None or lenses:
            lens_theses = list(lenses or [])
            if thesis:
                lens_theses.insert(0, thesis)
            payload = review_briefing_set(
                briefing,
                mode=selected_mode,
                width=width or len(lens_theses),
                theses=lens_theses,
                top_k=top_k,
                config_path=config_path,
            )
        else:
            payload = review_briefing(
                briefing,
                mode=selected_mode,
                thesis=thesis,
                config_path=config_path,
            )
    except (BundleError, ReviewError, LLMError, OSError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]Review failed:[/] {exc}")
        raise typer.Exit(code=2) from exc
    if json_output:
        _emit_json(payload)
        return
    _render_review(payload)


def _load_review_briefing(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ReviewError(f"review input does not exist: {path}")
    if path.suffix.lower() == ".r2br":
        return read_evidence_bundle(path).briefing
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReviewError("review input must be a JSON object")
    nested = value.get("briefing")
    if isinstance(nested, dict):
        return nested
    return value


def _render_review(payload: dict[str, Any]) -> None:
    if payload.get("schema_version") == "r2b.review-set.v1":
        _render_review_set(payload)
        return
    table = Table(title=f"Region review · {payload.get('mode')}")
    table.add_column("Rules", justify="right")
    table.add_column("Model", justify="right")
    table.add_column("Signal")
    table.add_column("Evidence")
    table.add_column("Region")
    model_order = payload.get("model_order")
    model_ranks = {
        str(item.get("region_id")): item.get("rank")
        for item in model_order if isinstance(item, dict)
    } if isinstance(model_order, list) else {}
    assessment = payload.get("noise_assessment")
    noise_rows = assessment.get("regions") if isinstance(assessment, dict) else []
    noise_by_region = {
        str(item.get("region_id")): item
        for item in noise_rows
        if isinstance(item, dict)
    } if isinstance(noise_rows, list) else {}
    for item in payload.get("base_order") or []:
        if not isinstance(item, dict):
            continue
        region_id = str(item.get("region_id") or "")
        noise = noise_by_region.get(region_id, {})
        table.add_row(
            str(item.get("rank") or "-"),
            str(model_ranks.get(region_id, "-")),
            str(noise.get("disposition") or "-").replace("_", " "),
            str(noise.get("claim_strength") or "-"),
            f"{item.get('title') or region_id} [dim]({region_id})[/]",
        )
    console.print(table)
    _render_noise_summary(payload)
    disagreements = payload.get("disagreements") or []
    if disagreements:
        console.print(f"[yellow]{len(disagreements)} rank disagreement(s)[/]")
    model = payload.get("model")
    if isinstance(model, dict):
        console.print(f"[dim]{model.get('provider')}/{model.get('model')} · tool rounds 0[/]")


def _render_review_set(payload: dict[str, Any]) -> None:
    overlay = payload.get("overlay") if isinstance(payload.get("overlay"), dict) else {}
    marginal = overlay.get("marginal") if isinstance(overlay, dict) else []
    table = Table(title=f"Review width · {payload.get('width')} · top {payload.get('top_k')}")
    table.add_column("Width", justify="right")
    table.add_column("New regions")
    table.add_column("Cumulative", justify="right")
    table.add_column("Passes", justify="right")
    table.add_column("Model calls", justify="right")
    for item in marginal if isinstance(marginal, list) else []:
        if not isinstance(item, dict):
            continue
        table.add_row(
            str(item.get("width")),
            ", ".join(str(value) for value in item.get("new_region_ids") or []) or "—",
            str(len(item.get("cumulative_region_ids") or [])),
            str(item.get("pass_count")),
            str(item.get("model_calls")),
        )
    console.print(table)
    _render_noise_summary(payload)
    console.print(
        "[dim]One briefing; independent fan-out; evidence IDs are deduplicated in the overlay.[/]"
    )


def _render_noise_summary(payload: dict[str, Any]) -> None:
    assessment = payload.get("noise_assessment")
    summary = assessment.get("summary") if isinstance(assessment, dict) else None
    if not isinstance(summary, dict):
        return
    behavior_ids = assessment.get("supported_behavior_region_ids")
    behavior_count = len(behavior_ids) if isinstance(behavior_ids, list) else 0
    console.print(
        "[dim]Evidence screen: "
        f"{summary.get('actionable', 0)} actionable · "
        f"{summary.get('needs_confirmation', 0)} needs confirmation · "
        f"{summary.get('low_signal', 0)} low-signal · "
        f"{behavior_count} supported behavior. "
        "Low-signal does not mean safe.[/]"
    )


@bundle_app.command("create")
def bundle_create(
    binary: Path = typer.Argument(..., help="Path to the binary or firmware subject"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output .r2br path"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    quick: bool = typer.Option(
        True,
        "--quick/--deep",
        help="Run the default triage scan; --deep enables the regular deep stage",
    ),
    max_regions: int = typer.Option(6, "--max-regions", help="Cap ranked regions"),
    include_target: bool = typer.Option(
        False,
        "--include-target",
        help="Embed target bytes; by default only their SHA-256 and size are stored",
    ),
    extract: bool = typer.Option(
        False,
        "--extract",
        help="Run sandboxed binwalk3/unblob and merge into the artifact DAG",
    ),
    review_width: int = typer.Option(
        0,
        "--review-width",
        min=0,
        max=MAX_REVIEW_WIDTH,
        help="Attach an independent multi-lens review; 0 disables review",
    ),
    review_mode: str = typer.Option(
        "rules",
        "--review-mode",
        help="Review engine: rules, llm, both (compare aliases both)",
    ),
    review_lenses: Optional[list[str]] = typer.Option(
        None,
        "--review-lens",
        help="Custom model lens thesis; repeatable",
    ),
    review_top: int = typer.Option(
        2,
        "--review-top",
        min=1,
        help="Regions from each pass included in the attached overlay",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit the validated bundle summary as JSON"),
) -> None:
    """Analyze a subject and write a portable, validated evidence bundle."""

    _require_binary(binary)
    destination = output or default_bundle_path(binary)
    state = build_state(config_path, persist=False)
    if extract:
        state.config.extract.enable = True
    plan = state.orchestrator.create_plan(quick_only=quick, skip_deep=False)
    result = state.orchestrator.analyze(binary, plan)
    public = analysis_result_to_public_dict(result)
    briefing = build_briefing(result, max_regions=max_regions)
    public["briefing"] = briefing
    review_payload = None
    try:
        if review_width or review_lenses:
            lens_theses = list(review_lenses or [])
            review_payload = review_briefing_set(
                briefing,
                mode=normalize_review_mode(review_mode),
                width=review_width or len(lens_theses),
                theses=lens_theses,
                top_k=review_top,
                config_path=config_path,
            )
        bundle = create_evidence_bundle(
            destination,
            briefing=briefing,
            analysis=public,
            tool_status=result.tool_status,
            review=review_payload,
            target=binary,
            include_target=include_target,
        )
    except (BundleError, ReviewError, LLMError) as exc:
        err_console.print(f"[red]Could not create bundle:[/] {exc}")
        raise typer.Exit(code=1) from exc
    summary = bundle.summary()
    if json_output:
        _emit_json(summary)
        return
    console.print(f"[green]Bundle[/] {destination}")
    console.print(f"[dim]SHA-256[/] {bundle.sha256}")
    if not include_target:
        console.print("[dim]Target bytes excluded (use --include-target to embed them).[/]")


@bundle_app.command("inspect")
def bundle_inspect(
    bundle: Path = typer.Argument(..., help="Path to an r2b evidence bundle"),
    json_output: bool = typer.Option(False, "--json", help="Emit the validated summary as JSON"),
) -> None:
    """Validate a bundle and show its content addresses and members."""

    try:
        summary = inspect_evidence_bundle(bundle)
    except BundleError as exc:
        err_console.print(f"[red]Invalid bundle:[/] {exc}")
        raise typer.Exit(code=1) from exc
    if json_output:
        _emit_json(summary)
        return
    subject = summary["subject"]
    console.rule(f"Bundle: {bundle.name}")
    console.print(f"[cyan]Schema[/] {summary['schema_version']}")
    console.print(f"[cyan]Bundle SHA-256[/] {summary['bundle_sha256']}")
    console.print(f"[cyan]Subject[/] {subject.get('name')}  {subject.get('sha256') or 'unknown hash'}")
    console.print(f"[cyan]Target bytes[/] {'included' if summary['target_included'] else 'excluded'}")
    console.print(f"[cyan]Members[/] {', '.join(summary['members'])}")



@app.command()
def verify(
    binary: Path = typer.Argument(..., help="Path to an ELF"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    imports: Optional[list[str]] = typer.Option(
        None, "--import", help="Import to verify. Repeatable. Default: system/popen/exec*"
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON verdicts"),
) -> None:
    """Classify the first argument at every call site of dangerous imports.

    Turns 'popen might be attacker-controlled' into 'popen arg is constant
    getfirm MAC' (or dynamic / no-callers) without a full decompile.
    """
    from .adapters.radare2 import Radare2Adapter
    from .analysis.verify import DEFAULT_IMPORTS

    _require_binary(binary)
    # Loading config applies the configured tool path and makes --config a
    # real option rather than an accepted-but-ignored argument.
    load_config(config_path)
    names = [item.strip() for item in (imports or list(DEFAULT_IMPORTS)) if item.strip()]
    adapter = Radare2Adapter()
    verdicts = adapter.verify_scan(binary, names)
    if json_output:
        _emit_json(
            {
                "schema_version": "r2b.verify.v1",
                "binary": str(binary),
                "verdicts": verdicts,
            }
        )
        return
    console.rule(f"Verify: {binary.name}")
    table = Table()
    table.add_column("Import")
    table.add_column("Status")
    table.add_column("Site")
    table.add_column("Function")
    table.add_column("Argument")
    decompile_addrs: list[str] = []
    seen_addrs: set[str] = set()
    for item in verdicts:
        sites = [site for site in (item.get("call_sites") or []) if isinstance(site, dict)]
        if not sites:
            table.add_row(str(item.get("import") or ""), str(item.get("status") or ""), "-", "-", "-")
            continue
        for site in sites:
            function_addr = str(site.get("function_addr") or "")
            table.add_row(
                str(item.get("import") or ""),
                str(item.get("status") or ""),
                str(site.get("address") or "-"),
                function_addr or str(site.get("function") or "-"),
                str(site.get("argument") or "-"),
            )
            if function_addr and function_addr not in seen_addrs:
                seen_addrs.add(function_addr)
                decompile_addrs.append(function_addr)
    console.print(table)
    quoted = str(binary)
    for addr in decompile_addrs[:4]:
        console.print(f"[dim]decompile[/] r2b decompile {quoted} {addr} --json")


@app.command()
def decompile(
    binary: Path = typer.Argument(..., help="Path to an ELF"),
    function: str = typer.Argument(
        ...,
        help="Function or call-site VA (hex). Resolved to the containing function.",
    ),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Decompile one function via Ghidra headless. Not a whole-binary import dump."""
    from .adapters.ghidra import GhidraAdapter

    _require_binary(binary)
    state = build_state(config_path, persist=False)
    if not state.env.ghidra or not state.env.ghidra.headless_ready:
        err_console.print(
            "[red]Ghidra headless not ready. Set GHIDRA_INSTALL_DIR and run `r2b ghidra status`."
        )
        raise typer.Exit(code=1)
    adapter = GhidraAdapter(
        detection=state.env.ghidra,
        project_dir=state.config.ghidra.project_dir,
        settings=state.config.ghidra,
    )
    payload = adapter.decompile_function(binary, function)
    if json_output:
        _emit_json(payload)
        return
    resolved = payload.get("function_addr") or function
    console.rule(f"Decompile {binary.name} @ {resolved}")
    if payload.get("function_addr") and str(payload["function_addr"]) != str(function):
        console.print(f"[dim]requested[/] {function}  [dim]resolved[/] {payload['function_addr']}")
    if not payload.get("success"):
        console.print("[red]Decompile failed[/]")
        if payload.get("stderr"):
            console.print(payload["stderr"])
    console.print(payload.get("c") or "")

@app.command("env")
def env_check(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of tables"),
) -> None:
    """Run environment diagnostics (tools, LLM key presence, Ghidra)."""

    config = load_config(config_path)
    report = detect_environment(config)
    if json_output:
        # Raw stdout so SSH/scripts can pipe this. Do not send it through Rich.
        _emit_json(report)
        return
    _render_env_report(report)
    try:
        plan = recommend_setup()
        console.print(
            f"[cyan]Recommended flavor[/] {plan['flavor']} — {plan['why']}\n"
            f"Run `r2b setup` (or `r2b setup --json`) to see the install plan."
        )
    except Exception:
        pass



@app.command("setup")
def setup_cmd(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    flavor: Optional[str] = typer.Option(
        None, "--flavor", help="core | lab | full. Default: sniff the host and pick."
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit r2b.setup.v1 JSON (stdout only)"),
    apply: bool = typer.Option(
        False, "--apply", help="uv sync the recommended extra only. Never sudo. Never writes $HOME."
    ),
    write_overlay: bool = typer.Option(
        False,
        "--write-overlay",
        help="Also copy config/flavors/<flavor>.toml to config/local.toml if that file is missing",
    ),
) -> None:
    """Sniff the box, recommend a flavor, optionally apply it.

    Least invasive: no sudo, no ~/.config, no overlay unless --write-overlay.
    """
    _ = config_path
    repo = find_checkout_root()
    try:
        plan = recommend_setup(flavor=flavor, repo_root=repo)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if json_output and not apply:
        _emit_json(plan)
        return

    if not json_output:
        console.rule(f"setup flavor={plan['flavor']}")
        console.print(plan["why"])
        host = plan["host"]
        console.print(
            f"host {host['os']}/{host['arch']}  {host['ram_gb']} GB  {host['cpus']} cpus"
            f"{'  (looks like a Pi)' if host['likely_pi'] else ''}"
        )
        if plan["missing"]:
            console.print("[red]missing:[/] " + ", ".join(row["name"] for row in plan["missing"]))
        if plan["skip"]:
            for row in plan["skip"]:
                console.print(f"[yellow]skip[/] {row['name']} — {row['reason']}")
        console.print("[cyan]commands[/]")
        for cmd in plan["commands"]:
            console.print(f"  {cmd}")
        for note in plan["notes"]:
            console.print(f"[dim]{note}")

    if apply:
        applied = _apply_setup(plan, repo_root=repo, write_overlay=write_overlay)
        if json_output:
            plan["applied"] = applied
            _emit_json(plan)
            return
        for line in applied:
            console.print(f"[green]applied[/] {line}")
        console.print("Next: `uv run r2b env --json` then `uv run r2b brief /bin/ls --quick --json`.")


def _apply_setup(
    plan: dict[str, Any], *, repo_root: Path | None, write_overlay: bool = False
) -> list[str]:
    import subprocess

    done: list[str] = []
    extra = str(plan.get("uv_extra") or "r2")
    flavor = str(plan.get("flavor") or "core")
    overlay_name = f"flavors/{flavor}.toml"
    overlay = shipped_config_dir() / overlay_name
    if repo_root is not None:
        local = repo_root / "config" / "local.toml"
        local_label = "config/local.toml"
    else:
        local = USER_CONFIG_PATH
        local_label = str(local)
    if write_overlay:
        if overlay.is_file() and not local.exists():
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_text(overlay.read_text(encoding="utf-8"), encoding="utf-8")
            done.append(f"wrote {local_label} from {overlay_name}")
        elif local.exists():
            done.append(f"{local_label} exists; left it alone")
        else:
            done.append(f"overlay {overlay_name} missing; skipped write")
    else:
        done.append("config untouched (pass --write-overlay to copy a flavor toml)")
    uv = shutil.which("uv")
    if not uv:
        done.append("uv not on PATH; skipped sync")
        return done
    if repo_root is None:
        if flavor == "full":
            pip_extra = "analyzers,std"
        elif flavor == "lab":
            pip_extra = "std"
        else:
            pip_extra = extra
        done.append(f"not a checkout; install extras with: uv pip install 'r2b[{pip_extra}]'")
        return done
    proc = subprocess.run(
        [uv, "sync", "--extra", extra],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        done.append(f"uv sync --extra {extra}")
    else:
        done.append(f"uv sync --extra {extra} failed rc={proc.returncode}")
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        if err:
            done.append(err[-1][:200])
    return done


@ghidra_app.command("status")
def ghidra_status(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of text"),
) -> None:
    """Show Ghidra headless/bridge readiness."""

    config = load_config(config_path)
    detection = detect_ghidra(config)
    if json_output:
        _emit_json(_ghidra_detection_to_dict(detection))
        return

    status = "[green]Ready" if detection.is_ready else "[red]Not ready"
    console.print(f"Ghidra: {status}")
    if detection.install_dir:
        console.print(f"Install dir: {detection.install_dir}")
    if detection.headless_path:
        console.print(f"Headless: {detection.headless_path}")
    bridge = "[green]connected" if detection.bridge_ready else "[yellow]not connected"
    console.print(f"Bridge: {bridge}")
    for issue in detection.issues:
        console.print(f"  • [red]{issue}")
    for note in detection.notes:
        console.print(f"  • [cyan]{note}")


@ghidra_app.command("setup")
def ghidra_setup(
    version: Optional[str] = typer.Option(
        None,
        "--version",
        "-v",
        help="Official Ghidra version to resolve via NSA/Ghidra release metadata, for example 11.4.2.",
    ),
    url: Optional[str] = typer.Option(None, "--url", help="Explicit Ghidra .zip archive URL."),
    archive: Optional[Path] = typer.Option(None, "--archive", help="Local Ghidra .zip archive to install."),
    install_root: Path = typer.Option(
        Path("~/.local/share/r2b/tools").expanduser(),
        "--install-root",
        help="Directory that will contain the extracted Ghidra installation.",
    ),
    force: bool = typer.Option(False, "--force", help="Replace an existing install directory."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Resolve and print the setup plan without downloading/extracting."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of text"),
) -> None:
    """Install Ghidra from a version, explicit URL, or local archive."""

    try:
        result = setup_ghidra(
            version=version,
            url=url,
            archive=archive,
            install_root=install_root,
            force=force,
            dry_run=dry_run,
        )
    except GhidraSetupError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if json_output:
        _emit_json(_ghidra_setup_to_dict(result))
        return

    title = "Ghidra setup plan" if result.dry_run else "Ghidra installed"
    table = Table(title=title, show_header=False)
    if result.version:
        table.add_row("Version", result.version)
    if result.archive_url:
        table.add_row("Archive URL", result.archive_url)
    if result.archive_path:
        table.add_row("Archive", str(result.archive_path))
    table.add_row("Install dir", str(result.install_dir))
    table.add_row("Headless", str(result.headless_path or "-"))
    console.print(table)
    console.print(result.env_line)
    if not result.dry_run:
        console.print("Run `uv run r2b ghidra status` after exporting GHIDRA_INSTALL_DIR.")


@app.command()
def trajectories(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
) -> None:
    """List stored analysis trajectories."""

    state = build_state(config_path)
    if not state.dao:
        console.print("[yellow]Storage disabled; configure storage.database_path to enable trajectories")
        raise typer.Exit(code=1)

    table = Table(title="Recent Trajectories")
    table.add_column("ID")
    table.add_column("Binary")
    table.add_column("Created")
    table.add_column("Completed")

    for trajectory in state.dao.list_recent():
        table.add_row(
            trajectory.trajectory_id,
            trajectory.binary_path,
            trajectory.created_at.isoformat(),
            trajectory.completed_at.isoformat() if trajectory.completed_at else "-",
        )

    console.print(table)


def _publish_session(state: AppState, result: Any, public: dict[str, Any]) -> Any | None:
    if not state.chat_dao:
        return None
    try:
        return publish_analysis_session(state.chat_dao, result, public)
    except Exception as exc:
        err_console.print(f"[yellow]Session not published: {exc}")
        return None


def _persist_record(
    state: AppState,
    result: Any,
    binary: Path,
    *,
    extra_tags: list[str] | None = None,
) -> dict[str, Any] | None:
    try:
        store = AnalysisRecordStore(Path(state.config.output.artifacts_dir))
        return store.persist(result, binary=binary, extra_tags=extra_tags)
    except Exception as exc:
        err_console.print(f"[yellow]Record not persisted: {exc}")
        return None


@records_app.command("list")
def records_list(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """List tagged analysis records."""
    state = build_state(config_path)
    store = AnalysisRecordStore(Path(state.config.output.artifacts_dir))
    rows = store.list_records(tag=tag)
    if json_output:
        _emit_json(rows)
        return
    table = Table(title="Analysis records")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Tags")
    table.add_column("Rev")
    table.add_column("Updated")
    for row in rows:
        names = ", ".join(str(name) for name in (row.get("names") or [])[:2]) or "-"
        tags = ", ".join(str(item) for item in (row.get("tags") or [])[:6])
        table.add_row(str(row.get("record_id") or "")[:16], names, tags, str(row.get("revision") or 1), str(row.get("updated_at") or ""))
    console.print(table)


@records_app.command("show")
def records_show(
    record_id: str = typer.Argument(..., help="SHA-256 (or unique prefix)"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    json_output: bool = typer.Option(False, "--json", help="Emit record JSON"),
    blobs: bool = typer.Option(False, "--blobs", help="Include tool/region/CFG blobs"),
) -> None:
    """Reopen a persisted analysis record."""
    state = build_state(config_path)
    store = AnalysisRecordStore(Path(state.config.output.artifacts_dir))
    resolved = _resolve_record_id(store, record_id)
    record = store.load(resolved, include_blobs=blobs)
    if not record:
        raise typer.BadParameter(f"Record not found: {record_id}")
    if json_output:
        _emit_json(record)
        return
    console.rule(f"Record {record.get('record_id')}")
    table = Table(show_header=False)
    table.add_row("Directory", str(record.get("directory")))
    table.add_row("Names", ", ".join(record.get("names") or []))
    table.add_row("Tags", ", ".join(record.get("tags") or []))
    table.add_row("Revision", str(record.get("revision")))
    table.add_row("Tools", ", ".join(record.get("tool_names") or []))
    table.add_row("Regions", str(record.get("region_count")))
    table.add_row("CFGs", str(record.get("cfg_count")))
    console.print(table)
    commentary_path = Path(str(record.get("directory") or "")) / "commentary.md"
    if commentary_path.is_file():
        console.print(commentary_path.read_text(encoding="utf-8"))


@app.command()
def insights(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Restrict to a tag"),
    record_id: Optional[str] = typer.Option(None, "--record", help="Focus on siblings of this record"),
    save: bool = typer.Option(False, "--save", help="Write a lab note under artifacts/insights/"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Distill recurring facts from persisted records. Not a skill writer."""
    state = build_state(config_path)
    store = AnalysisRecordStore(Path(state.config.output.artifacts_dir))
    focus = _resolve_record_id(store, record_id) if record_id else None
    payload = extract_insights(store, focus_id=focus, tag=tag)
    if json_output:
        _emit_json(payload)
        return
    if not payload.get("ready"):
        console.print(f"[yellow]{payload.get('reason')}")
        return
    family = payload.get("family") or {}
    family_label = "/".join(
        part for part in (family.get("subject_class"), family.get("id")) if part
    )
    title = f"Insights from {payload.get('sibling_count')} records"
    if family_label:
        title += f" ({family_label})"
    console.rule(title)
    others = [
        item
        for item in (payload.get("families") or [])
        if (item.get("subject_class"), item.get("id"))
        != (family.get("subject_class"), family.get("id"))
    ]
    if others:
        bits = ", ".join(f"{item.get('subject_class')}/{item.get('id')} x{item.get('count')}" for item in others)
        console.print(f"[dim]Other families not mixed in: {bits}[/]")
    for pattern in payload.get("patterns") or []:
        console.print(f"[bold]{pattern.get('title')}[/]")
        console.print(f"  {pattern.get('why')}")
        console.print(f"  next: {pattern.get('next_action')}")
    console.print(payload.get("skill_hint") or "")
    if save:
        path = save_lab_note(store, payload)
        console.print(f"[cyan]Lab note[/] {path}")


def _resolve_record_id(store: AnalysisRecordStore, record_id: str) -> str:
    text = record_id.strip().lower()
    if len(text) >= 64:
        return text
    matches = [row for row in store.list_records(limit=500) if str(row.get("record_id") or "").startswith(text)]
    if len(matches) == 1:
        return str(matches[0]["record_id"])
    if not matches:
        return text
    raise typer.BadParameter(f"Ambiguous record id {record_id}; matches {len(matches)}")


def _ask_briefing(
    state: AppState,
    briefing: dict[str, Any],
    *,
    question: str | None,
    region_count: int,
    out: Console | None = None,
) -> tuple[bool, dict[str, Any] | None]:
    """Send compact briefing asks instead of dumping adapter JSON.

    Returns (ok, payload). ok is False if any ask came back empty after retry
    (harness: exit 2). payload is attached to --json as ask_result.
    """
    stream = out or console
    asks: list[tuple[str, str]] = []
    if question:
        asks.append(("overall", question))
    for region in (briefing.get("regions") or [])[: max(0, region_count)]:
        if isinstance(region, dict) and region.get("ask"):
            asks.append((str(region.get("title") or region.get("id") or "region"), str(region["ask"])))
    if not asks:
        return True, None

    bridge = LLMBridge(state.config)
    context = render_briefing_markdown(briefing, include_asks=False)
    system = ANALYST_SYSTEM
    answered = True
    answers: list[dict[str, Any]] = []
    for title, ask_text in asks:
        messages = [
            LLMChatMessage(role="system", content=system),
            LLMChatMessage(role="user", content=f"{ask_text}\n\nBriefing:\n{context}"),
        ]
        response = ""
        try:
            response = (bridge.chat(messages) or "").strip()
            if not response:
                # Empty bodies arrive with HTTP 200 on some gateways; retry
                # once, then fail the ask loudly instead of printing nothing.
                response = (bridge.chat(messages) or "").strip()
        except (LLMError, RuntimeError) as exc:
            stream.print(f"[red]LLM unavailable: {exc}")
            return False, {
                "ok": False,
                "provider": None,
                "error": str(exc),
                "answers": answers,
            }
        stream.rule(f"LLM ({bridge.last_provider or 'unknown'}): {title}")
        if not response:
            stream.print(f"[red]EMPTY RESPONSE -- ask not answered (provider={bridge.last_provider})")
            answered = False
            answers.append(
                {
                    "title": title,
                    "text": "",
                    "provider": bridge.last_provider,
                    "cited": None,
                }
            )
            continue
        stream.print(response)
        cited = parse_cited_claims(response)
        answers.append(
            {
                "title": title,
                "text": response,
                "provider": bridge.last_provider,
                "cited": cited,
            }
        )
        if cited["uncited"]:
            stream.print(
                f"[yellow]{len(cited['uncited'])} uncited claim(s) — treat as ungrounded; "
                "names/types stay proposed until a human accepts."
            )
        elif cited["proposed"]:
            stream.print("[yellow]Model-produced names/types are proposed annotations, not facts.")
    return answered, {
        "ok": answered,
        "provider": bridge.last_provider,
        "answers": answers,
    }


def _render_result(result: Any) -> None:
    console.rule(f"Analysis: {result.binary.name}")
    meta = result.quick_scan.get("identification", {})
    info = result.quick_scan.get("radare2", {}).get("info", {}) if isinstance(result.quick_scan.get("radare2"), dict) else {}

    table = Table(show_header=False)
    table.add_row("Binary", str(result.binary))
    table.add_row("Type", str(meta.get("description", "unknown")))
    if isinstance(info, dict):
        bin_info = info.get("bin", {})
        if isinstance(bin_info, dict):
            table.add_row("Arch", str(bin_info.get("arch", "?")))
            table.add_row("Bits", str(bin_info.get("bits", "?")))
    console.print(table)

    if result.issues:
        console.print("[red]Issues:")
        for issue in result.issues:
            console.print(f"  • {issue}")

    if result.notes:
        console.print("[cyan]Notes:")
        for note in result.notes:
            console.print(f"  • {note}")


def _render_env_report(report: EnvironmentReport) -> None:
    console.rule("Environment Report")
    if report.llm:
        llm_table = Table(title="LLM")
        llm_table.add_column("Field")
        llm_table.add_column("Value")
        llm_table.add_row("Provider", report.llm.provider)
        llm_table.add_row("Model", report.llm.model)
        llm_table.add_row("Key env", report.llm.api_key_env or "-")
        llm_table.add_row("Key present", "yes" if report.llm.api_key_present else "no")
        llm_table.add_row("Provider URL", report.llm.base_url or "-")
        if report.llm.hint:
            llm_table.add_row("Hint", report.llm.hint)
        console.print(llm_table)

    table = Table(title="Tooling")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Details")
    for tool in report.tools:
        status = "[green]OK" if tool.available else "[red]Missing"
        table.add_row(tool.name, status, tool.version or tool.details or "")
    console.print(table)

    if report.ghidra:
        ghidra_status = "[green]Ready" if report.ghidra.is_ready else "[red]Not ready"
        console.print(f"Ghidra: {ghidra_status}")
        for issue in report.ghidra.issues:
            console.print(f"  • [red]{issue}")
        for note in report.ghidra.notes:
            console.print(f"  • [cyan]{note}")

    if report.issues:
        console.print("[red]Blocking issues detected:")
        for issue in report.issues:
            console.print(f"  • {issue}")

    if report.notes:
        console.print("[cyan]Notes:")
        for note in report.notes:
            console.print(f"  • {note}")



def _ghidra_setup_to_dict(result: GhidraSetupResult) -> dict[str, Any]:
    return {
        "archive_url": result.archive_url,
        "archive_path": str(result.archive_path) if result.archive_path else None,
        "install_dir": str(result.install_dir),
        "headless_path": str(result.headless_path) if result.headless_path else None,
        "version": result.version,
        "dry_run": result.dry_run,
        "ready": result.ready,
        "env": result.env_line,
    }


def _ghidra_detection_to_dict(detection: Any) -> dict[str, Any]:
    return {
        "install_dir": str(detection.install_dir) if detection.install_dir else None,
        "headless_path": str(detection.headless_path) if detection.headless_path else None,
        "bridge_available": detection.bridge_available,
        "bridge_connected": detection.bridge_connected,
        "bridge_program_loaded": detection.bridge_program_loaded,
        "extension_root": str(detection.extension_root),
        "issues": detection.issues,
        "notes": detection.notes,
        "ready": detection.is_ready,
    }



def _pilot_root(root: Optional[Path]) -> Path:
    return Path(root).resolve() if root else Path.cwd().resolve()


@pilot_app.command("plan")
def pilot_plan(
    goal: str = typer.Option(..., "--goal", help="What the run should accomplish"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    root: Optional[Path] = typer.Option(None, "--root", help="Lab corpus root (holds samples/ and work/)"),
) -> None:
    """Ask the planner for a validated plan JSON (makes an LLM call)."""
    engine = build_engine(config_path, _pilot_root(root))
    plan, errs, _raw = engine.plan(goal)
    if not plan:
        console.print(f"[red]planner reply was not JSON:[/] {errs}")
        raise typer.Exit(code=1)
    _emit_json(plan)
    if errs:
        console.print(f"[red]plan invalid:[/] {errs}")
        raise typer.Exit(code=1)
    console.print("plan valid")


@pilot_app.command("run")
def pilot_run(
    goal: str = typer.Option(..., "--goal", help="What the run should accomplish"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    root: Optional[Path] = typer.Option(None, "--root", help="Lab corpus root (holds samples/ and work/)"),
    max_steps: int = typer.Option(3, "--max-steps", help="Cap on executed steps per plan"),
    followup: bool = typer.Option(True, "--followup/--no-followup", help="Allow one follow-up round"),
    timeout: int = typer.Option(900, "--timeout", help="Per-step subprocess timeout (seconds)"),
) -> None:
    """Full run: plan, execute steps, report, optional follow-up round."""
    engine = build_engine(config_path, _pilot_root(root))
    engine.do_run(goal, max_steps=max_steps, followup=followup, timeout=timeout)


@pilot_app.command("enqueue")
def pilot_enqueue_cmd(
    goal: str = typer.Option(..., "--goal", help="What the run should accomplish"),
    root: Optional[Path] = typer.Option(None, "--root", help="Lab corpus root (holds samples/ and work/)"),
    max_steps: int = typer.Option(3, "--max-steps", help="Cap on executed steps per plan"),
    followup: bool = typer.Option(True, "--followup/--no-followup", help="Allow one follow-up round"),
) -> None:
    """Drop a goal into <root>/work/pilot/queue/ for the watcher."""
    job = pilot_enqueue(pilot_dir_for(_pilot_root(root)) / "queue", goal,
                        max_steps=max_steps, followup=followup)
    console.print(f"queued {job}")


@pilot_app.command("watch")
def pilot_watch_cmd(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    root: Optional[Path] = typer.Option(None, "--root", help="Lab corpus root (holds samples/ and work/)"),
    once: bool = typer.Option(False, "--once", help="Process one job then exit"),
    interval: int = typer.Option(5, "--interval", help="Queue poll interval (seconds)"),
) -> None:
    """Process goals from work/pilot/queue/ (run under a service manager)."""
    engine = build_engine(config_path, _pilot_root(root))
    raise typer.Exit(code=pilot_watch(engine, once=once, interval=interval))


@pilot_app.command("status")
def pilot_status_cmd(
    root: Optional[Path] = typer.Option(None, "--root", help="Lab corpus root (holds samples/ and work/)"),
    run: Optional[str] = typer.Argument(None, help="Restrict to one run id"),
) -> None:
    """List pilot runs and their step states."""
    raise typer.Exit(code=pilot_status(pilot_dir_for(_pilot_root(root)), run))


@pilot_app.command("logs")
def pilot_logs_cmd(
    run: str = typer.Argument(..., help="Run id"),
    n: str = typer.Argument("00", help="Step number or prefix (e.g. 00 or 00-analyze)"),
    root: Optional[Path] = typer.Option(None, "--root", help="Lab corpus root (holds samples/ and work/)"),
) -> None:
    """Print one step log."""
    sys.stdout.write(pilot_step_log(pilot_dir_for(_pilot_root(root)), run, n))


@pilot_app.command("report")
def pilot_report_cmd(
    run: str = typer.Argument(..., help="Run id"),
    root: Optional[Path] = typer.Option(None, "--root", help="Lab corpus root (holds samples/ and work/)"),
) -> None:
    """Print a run's report.md."""
    sys.stdout.write(pilot_report_text(pilot_dir_for(_pilot_root(root)), run))


def run() -> None:
    app()
