"""r2brief public Python API."""

from importlib.metadata import PackageNotFoundError, version

from .api import (
    AnalysisOptions,
    AnalysisProfile,
    AnalysisReport,
    EvidenceRegion,
    ReviewMode,
    analyze,
    ask,
    brief,
    review,
    verify,
)

__all__ = [
    "AnalysisOptions",
    "AnalysisProfile",
    "AnalysisReport",
    "EvidenceRegion",
    "ReviewMode",
    "__version__",
    "analyze",
    "ask",
    "brief",
    "review",
    "verify",
]

try:  # pragma: no cover - metadata probe
    __version__ = version("r2b")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.1.0"
