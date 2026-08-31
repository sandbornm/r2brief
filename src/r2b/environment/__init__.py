"""Environment detection utilities."""

from .detectors import EnvironmentReport, detect_environment
from .setup import HostFacts, recommend_flavor, recommend_setup, sniff_host

__all__ = [
    "EnvironmentReport",
    "HostFacts",
    "detect_environment",
    "recommend_flavor",
    "recommend_setup",
    "sniff_host",
]
