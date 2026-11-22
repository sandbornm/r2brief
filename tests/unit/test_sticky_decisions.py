"""Accepted and rejected decisions survive a later proposed retry."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from r2b.config import AnalysisSettings, AppConfig, OutputSettings, StorageSettings
from r2b.storage import ChatDAO, Database


@pytest.fixture
def api(tmp_path: Path):
    from r2b.web.app import create_app

    config = AppConfig()
    config.storage = StorageSettings(database_path=tmp_path / "test.db", auto_migrate=True)
    config.analysis = AnalysisSettings(enable_angr=False, enable_ghidra=False, require_elf=False)
    config.output = OutputSettings(artifacts_dir=tmp_path / "artifacts")
    with patch.dict("os.environ", {"R2B_WEB_DEBUG": "false"}), patch("r2b.state.load_config", return_value=config):
        app = create_app()
        app.config["TESTING"] = True
        session = ChatDAO(Database(config.storage.database_path)).get_or_create_session(
            "/tmp/sample.bin",
            title="sample",
        )
        with app.test_client() as client:
            yield client, session.session_id


def test_accepted_function_name_survives_proposed_retry(api) -> None:
    client, session_id = api
    accepted = client.post(
        f"/api/chats/{session_id}/function-names",
        json={
            "address": "0x1000",
            "originalName": "sub_1000",
            "displayName": "parse_header",
            "source": "llm",
            "status": "accepted",
        },
    )
    assert accepted.status_code == 200

    proposed = client.post(
        f"/api/chats/{session_id}/function-names",
        json={
            "address": "0x1000",
            "originalName": "sub_1000",
            "displayName": "guess_name",
            "source": "llm",
            "status": "proposed",
        },
    )
    assert proposed.status_code == 200

    listed = client.get(f"/api/chats/{session_id}/function-names")
    assert listed.status_code == 200
    row = listed.get_json()["function_names"][0]
    assert row["address"] == "0x1000"
    assert row["status"] == "accepted"
    assert row["displayName"] == "parse_header"


def test_rejected_function_name_survives_proposed_retry(api) -> None:
    client, session_id = api
    client.post(
        f"/api/chats/{session_id}/function-names",
        json={
            "address": "0x1000",
            "originalName": "sub_1000",
            "displayName": "sub_1000",
            "source": "llm",
            "status": "rejected",
        },
    )
    client.post(
        f"/api/chats/{session_id}/function-names",
        json={
            "address": "0x1000",
            "originalName": "sub_1000",
            "displayName": "guess_name",
            "source": "llm",
            "status": "proposed",
        },
    )

    row = client.get(f"/api/chats/{session_id}/function-names").get_json()["function_names"][0]
    assert row["status"] == "rejected"
    assert row["displayName"] == "sub_1000"


def test_accepted_annotation_survives_proposed_retry(api) -> None:
    client, session_id = api
    body = {
        "id": "ann-0x1000",
        "kind": "name",
        "address": "0x1000",
        "source": "llm",
        "payload": {"text": "parse_header"},
    }
    accepted = client.post(
        f"/api/chats/{session_id}/proposed-annotations",
        json={**body, "status": "accepted"},
    )
    assert accepted.status_code == 200
    proposed = client.post(
        f"/api/chats/{session_id}/proposed-annotations",
        json={**body, "status": "proposed", "payload": {"text": "guess_name"}},
    )
    assert proposed.status_code == 200

    listed = client.get(f"/api/chats/{session_id}/proposed-annotations")
    assert listed.status_code == 200
    row = listed.get_json()["annotations"][0]
    assert row["id"] == "ann-0x1000"
    assert row["address"] == "0x1000"
    assert row["status"] == "accepted"
    assert row["payload"]["text"] == "parse_header"


def test_proposed_retry_still_refreshes_an_open_proposal(api) -> None:
    client, session_id = api
    client.post(
        f"/api/chats/{session_id}/function-names",
        json={
            "address": "0x1000",
            "originalName": "sub_1000",
            "displayName": "first_guess",
            "source": "llm",
            "status": "proposed",
        },
    )
    client.post(
        f"/api/chats/{session_id}/function-names",
        json={
            "address": "0x1000",
            "originalName": "sub_1000",
            "displayName": "second_guess",
            "source": "llm",
            "status": "proposed",
        },
    )
    row = client.get(f"/api/chats/{session_id}/function-names").get_json()["function_names"][0]
    assert row["status"] == "proposed"
    assert row["displayName"] == "second_guess"

    client.post(
        f"/api/chats/{session_id}/function-names",
        json={
            "address": "0x1000",
            "originalName": "sub_1000",
            "displayName": "sub_1000",
            "source": "llm",
            "status": "rejected",
        },
    )
    row = client.get(f"/api/chats/{session_id}/function-names").get_json()["function_names"][0]
    assert row["status"] == "rejected"
    assert row["displayName"] == "sub_1000"


def test_rejected_annotation_survives_proposed_retry(api) -> None:
    client, session_id = api
    body = {
        "id": "ann-0x1000",
        "kind": "name",
        "address": "0x1000",
        "source": "llm",
        "payload": {"text": "sub_1000"},
    }
    client.post(
        f"/api/chats/{session_id}/proposed-annotations",
        json={**body, "status": "rejected"},
    )
    client.post(
        f"/api/chats/{session_id}/proposed-annotations",
        json={**body, "status": "proposed", "payload": {"text": "guess_name"}},
    )

    row = client.get(f"/api/chats/{session_id}/proposed-annotations").get_json()["annotations"][0]
    assert row["status"] == "rejected"
    assert row["payload"]["text"] == "sub_1000"
