from pathlib import Path

from r2b.analysis.handoff import publish_analysis_session
from r2b.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2b.analysis.result_dto import analysis_result_to_public_dict
from r2b.storage import ChatDAO, Database


def test_publish_analysis_session_is_what_the_ui_restores(tmp_path: Path):
    binary = tmp_path / "httpd"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 16)
    result = AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(deep=False),
        quick_scan={"radare2": {"info": {"bin": {"arch": "arm"}}}},
        notes=["headless"],
    )
    dao = ChatDAO(Database(tmp_path / "r2b.db"))
    public = analysis_result_to_public_dict(result, include_briefing=False)
    session = publish_analysis_session(dao, result, public)

    listed = dao.list_sessions()
    assert listed[0].session_id == session.session_id
    messages = dao.list_messages(session.session_id)
    attachment = messages[0].attachments[0]
    assert attachment["type"] == "analysis_result"
    assert attachment["session_id"] == session.session_id
    assert attachment["notes"] == ["headless"]
    assert attachment["binary"].endswith("httpd")
