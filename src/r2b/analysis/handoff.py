from __future__ import annotations

from pathlib import Path
from typing import Any

from ..storage.chat import ChatDAO
from ..storage.models import ChatSession
from .orchestrator import AnalysisResult


def publish_analysis_session(
    chat_dao: ChatDAO,
    result: AnalysisResult,
    public: dict[str, Any],
    *,
    title: str | None = None,
) -> ChatSession:
    path = Path(str(result.binary))
    session = chat_dao.get_or_create_session(
        str(path),
        trajectory_id=result.trajectory_id,
        title=title or path.name,
    )
    payload = dict(public)
    payload["session_id"] = session.session_id
    if result.trajectory_id:
        payload["trajectory_id"] = result.trajectory_id
    chat_dao.append_message(
        session.session_id,
        "system",
        f"Analysis completed for {path.name}",
        attachments=[payload],
    )
    return session


__all__ = ["publish_analysis_session"]
