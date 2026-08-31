"""WSGI/CLI helpers to run the r2b web app."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_WEB_EXTRA_HINT = "r2b-web needs extra 'web'. Install with: uv sync --extra web"


def run(config_path: Optional[str] = None) -> None:
    """Start the development web server."""

    try:
        from werkzeug.serving import run_simple

        from .app import create_app
    except ModuleNotFoundError as exc:
        missing = (getattr(exc, "name", None) or str(exc)).lower()
        if "flask" in missing or "werkzeug" in missing:
            raise SystemExit(_WEB_EXTRA_HINT) from exc
        raise

    resolved_config = Path(config_path).expanduser() if config_path else None
    app = create_app(resolved_config)

    host = os.getenv("R2B_WEB_HOST") or os.getenv("R2B_WEB_HOST", "127.0.0.1")
    port = int(os.getenv("R2B_WEB_PORT") or os.getenv("R2B_WEB_PORT", "5050"))
    debug_value = os.getenv("R2B_WEB_DEBUG") or os.getenv("R2B_WEB_DEBUG", "false")
    debug = debug_value.strip().lower() in {"1", "true", "yes", "on"}

    run_simple(hostname=host, port=port, application=app, use_debugger=debug, use_reloader=debug)


__all__ = ["run"]
