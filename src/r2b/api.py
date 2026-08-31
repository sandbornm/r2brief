"""Small, typed public API for embedding r2brief."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Collection, Literal, Mapping, Sequence

from r2b.analysis.briefing import build_briefing, render_briefing_markdown
from r2b.analysis.orchestrator import AnalysisOrchestrator, AnalysisResult
from r2b.analysis.review import ReviewMode, review_briefing
from r2b.analysis.result_dto import analysis_result_to_public_dict
from r2b.config import AppConfig, load_config
from r2b.environment import EnvironmentReport, detect_environment

if TYPE_CHECKING:
    from r2b.llm import FunctionTool, LLMBridge, LLMResponse, ToolCall

AnalysisProfile = Literal["triage", "standard", "exhaustive"]


@dataclass(frozen=True, slots=True)
class AnalysisOptions:
    """Control one analysis without mutating global or on-disk state.

    ``triage`` is the inexpensive default.  ``standard`` enables the regular
    deep stage, while ``exhaustive`` also permits heavy analyzers explicitly
    enabled in the supplied configuration.  Library calls do not create a
    database, chat session, record, or trajectory unless the caller builds
    those internal services itself.
    """

    profile: AnalysisProfile = "triage"
    extract: bool = False
    max_regions: int = 6

    def __post_init__(self) -> None:
        if self.profile not in {"triage", "standard", "exhaustive"}:
            raise ValueError(f"Unsupported analysis profile: {self.profile}")
        if not 1 <= self.max_regions <= 50:
            raise ValueError("max_regions must be between 1 and 50")


@dataclass(frozen=True, slots=True)
class EvidenceRegion:
    """Small, self-contained region context for humans, tools, or an optional LLM."""

    binary: str
    subject: Mapping[str, Any]
    payload: Mapping[str, Any]

    @property
    def id(self) -> str:
        return str(self.payload.get("id") or "")

    @property
    def title(self) -> str:
        return str(self.payload.get("title") or "")

    @property
    def why(self) -> str:
        return str(self.payload.get("why") or "")

    @property
    def score(self) -> float:
        value = self.payload.get("score")
        return float(value) if isinstance(value, (int, float)) else 0.0

    @property
    def evidence(self) -> dict[str, Any]:
        snippet = self.payload.get("snippet")
        source = dict(snippet) if isinstance(snippet, Mapping) else {}
        return {
            "id": self.id,
            "source": source.get("source"),
            "address": source.get("address"),
            "function": source.get("function"),
            "snippet": source.get("text"),
            "why": self.why,
        }

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)

    def to_briefing(self) -> dict[str, Any]:
        """Return the minimum versioned briefing needed to interpret this region."""
        region = self.to_dict()
        return {
            "schema_version": "r2b.briefing.v1",
            "binary": self.binary,
            "summary": f"Scoped evidence region: {self.title}.",
            "subject": dict(self.subject),
            "regions": [region],
            "overall_ask": "",
            "next_steps": list(region.get("next_actions") or []),
            "handoff": {
                "schema_version": "r2b.handoff.v1",
                "binary": self.binary,
                "regions": [region],
                "next_argv": [],
            },
        }

    def ask(self, question: str, **kwargs: Any) -> LLMResponse:
        """Ask about only this evidence capsule; execution controls remain host-owned."""
        return ask(self.to_briefing(), question, **kwargs)


@dataclass(slots=True)
class AnalysisReport:
    """Typed handle over the stable public payload and internal result."""

    result: AnalysisResult
    payload: dict[str, Any]
    briefing: dict[str, Any]

    @property
    def binary(self) -> Path:
        return self.result.binary

    @property
    def subject(self) -> dict[str, Any]:
        value = self.briefing.get("subject")
        return value if isinstance(value, dict) else {}

    @property
    def handoff(self) -> dict[str, Any]:
        value = self.briefing.get("handoff")
        return value if isinstance(value, dict) else {}

    @property
    def issues(self) -> tuple[str, ...]:
        return tuple(self.result.issues)

    @property
    def regions(self) -> tuple[EvidenceRegion, ...]:
        values = self.briefing.get("regions")
        if not isinstance(values, list):
            return ()
        return tuple(
            EvidenceRegion(str(self.binary), self.subject, region)
            for region in values
            if isinstance(region, Mapping)
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached JSON-serializable payload."""
        return dict(self.payload)

    def ask(
        self,
        question: str,
        **kwargs: Any,
    ) -> LLMResponse:
        """Ask a model about this report; see :func:`ask` for controls."""
        return ask(self, question, **kwargs)

    def review(self, **kwargs: Any) -> dict[str, Any]:
        """Compare the immutable rule order with an optional model order."""
        return review(self, **kwargs)


def analyze(
    binary: str | Path,
    *,
    options: AnalysisOptions | None = None,
    config: AppConfig | None = None,
    config_path: str | Path | None = None,
    environment: EnvironmentReport | None = None,
) -> AnalysisReport:
    """Analyze ``binary`` without implicit persistence or an LLM call.

    Pass either an already-loaded ``config`` or ``config_path``, not both.
    Providing ``environment`` lets harnesses cache an environment probe across
    several binaries.
    """
    path = Path(binary).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary path does not exist or is not a file: {path}")
    if config is not None and config_path is not None:
        raise ValueError("Pass config or config_path, not both")

    opts = options or AnalysisOptions()
    loaded = config.model_copy(deep=True) if config is not None else load_config(
        Path(config_path).expanduser() if config_path is not None else None
    )
    loaded.analysis.enable_trajectory_recording = False
    if opts.extract:
        loaded.extract.enable = True

    env = environment or detect_environment(loaded)
    orchestrator = AnalysisOrchestrator(loaded, env)
    plan = orchestrator.create_plan(
        quick_only=opts.profile == "triage",
        profile=opts.profile,
    )
    result = orchestrator.analyze(path, plan)
    briefing = build_briefing(result, max_regions=opts.max_regions)
    payload = analysis_result_to_public_dict(result, briefing=briefing)
    return AnalysisReport(result=result, payload=payload, briefing=briefing)


def brief(
    binary: str | Path,
    *,
    options: AnalysisOptions | None = None,
    config: AppConfig | None = None,
    config_path: str | Path | None = None,
    environment: EnvironmentReport | None = None,
) -> dict[str, Any]:
    """Return the stable ``r2b.briefing.v1`` mapping for ``binary``."""
    return analyze(
        binary,
        options=options,
        config=config,
        config_path=config_path,
        environment=environment,
    ).briefing


def verify(binary: str | Path, imports: list[str] | tuple[str, ...] | None = None) -> dict[str, Any]:
    """Resolve first arguments at dangerous-import call sites with radare2."""
    from r2b.adapters.radare2 import Radare2Adapter
    from r2b.analysis.verify import DEFAULT_IMPORTS

    path = Path(binary).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary path does not exist or is not a file: {path}")
    names = [str(name).strip() for name in (imports or DEFAULT_IMPORTS) if str(name).strip()]
    return {"binary": str(path), "verdicts": Radare2Adapter().verify_scan(path, names)}


def ask(
    analysis: AnalysisReport | Mapping[str, Any],
    question: str,
    *,
    bridge: LLMBridge | None = None,
    config: AppConfig | None = None,
    config_path: str | Path | None = None,
    tools: Sequence[FunctionTool] = (),
    tool_executor: Callable[[ToolCall], Any]
    | Mapping[str, Callable[[Mapping[str, Any]], Any]]
    | None = None,
    allowed_tools: Collection[str] | None = None,
    max_tool_rounds: int | None = None,
) -> LLMResponse:
    """Ask an optional LLM to interpret deterministic analysis evidence.

    Tool execution remains host-owned: declaring a tool does not execute it.
    A callback and explicit allowlist are both required, and the bridge caps
    the number of rounds.  Pass a preconfigured ``bridge`` to reuse provider
    state, or pass ``config``/``config_path`` and let this helper create one.
    """
    from r2b.llm import ANALYST_SYSTEM, ChatMessage, LLMBridge

    if not question.strip():
        raise ValueError("question must not be empty")
    if bridge is not None and (config is not None or config_path is not None):
        raise ValueError("Pass bridge or config/config_path, not both")
    if config is not None and config_path is not None:
        raise ValueError("Pass config or config_path, not both")

    briefing = analysis.briefing if isinstance(analysis, AnalysisReport) else dict(analysis)
    llm = bridge
    if llm is None:
        loaded = config or load_config(
            Path(config_path).expanduser() if config_path is not None else None
        )
        llm = LLMBridge(loaded)
    context = render_briefing_markdown(briefing, include_asks=False)
    return llm.generate(
        [
            ChatMessage(role="system", content=ANALYST_SYSTEM),
            ChatMessage(role="user", content=f"{question.strip()}\n\n{context}"),
        ],
        tools=tools,
        tool_executor=tool_executor,
        allowed_tools=allowed_tools,
        max_tool_rounds=max_tool_rounds,
    )


def review(
    analysis: AnalysisReport | Mapping[str, Any],
    *,
    mode: ReviewMode | str = "rules",
    thesis: str | None = None,
    bridge: LLMBridge | None = None,
    config: AppConfig | None = None,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create a versioned rules/model review without changing the briefing.

    ``rules`` makes no model call. ``llm`` asks a configured model to return an
    exact permutation of known region IDs. ``both`` also reports rank
    disagreements. Model tool execution is disabled in ``r2b.review.v1``.
    """

    if isinstance(analysis, AnalysisReport):
        briefing = analysis.briefing
    else:
        source = dict(analysis)
        nested = source.get("briefing")
        briefing = dict(nested) if isinstance(nested, Mapping) else source
    return review_briefing(
        briefing,
        mode=mode,
        thesis=thesis,
        bridge=bridge,
        config=config,
        config_path=config_path,
    )


__all__ = [
    "AnalysisOptions",
    "AnalysisProfile",
    "AnalysisReport",
    "EvidenceRegion",
    "ReviewMode",
    "analyze",
    "ask",
    "brief",
    "review",
    "verify",
]
