"""SQLite database helpers."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def _annotation_id(session_id: str, row: dict[str, Any]) -> str:
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
    text = str(payload.get("text") or row.get("text") or "")[:80]
    key = f"{session_id}:{row.get('kind')}:{row.get('address') or ''}:{text}"
    return hashlib.sha256(key.encode()).hexdigest()[:24]


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    names = {str(row[1]) for row in rows}
    if column not in names:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


class Database:
    """Thin wrapper around sqlite3 for app needs."""

    def __init__(self, path: Path) -> None:
        self._path = path.expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @property
    def path(self) -> Path:
        return self._path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _ensure_schema(self) -> None:
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS trajectories (
                    trajectory_id TEXT PRIMARY KEY,
                    binary_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    notes TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS trajectory_actions (
                    trajectory_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    payload TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (trajectory_id, seq),
                    FOREIGN KEY (trajectory_id) REFERENCES trajectories (trajectory_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_sessions (
                    session_id TEXT PRIMARY KEY,
                    binary_path TEXT NOT NULL,
                    trajectory_id TEXT,
                    title TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    message_count INTEGER DEFAULT 0
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_messages (
                    message_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    attachments TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions (session_id) ON DELETE CASCADE
                )
                """
            )
            
            # Annotations for disassembly lines
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS annotations (
                    annotation_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    binary_path TEXT NOT NULL,
                    address TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions (session_id) ON DELETE CASCADE,
                    UNIQUE (session_id, address)
                )
                """
            )
            
            # User activity events for context tracking
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS activity_events (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_data TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions (session_id) ON DELETE CASCADE
                )
                """
            )
            
            # Index for efficient activity lookups
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_activity_session_time
                ON activity_events (session_id, created_at DESC)
                """
            )

            # Function names for LLM-suggested or human-overridden function names
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS function_names (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    address TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    reasoning TEXT,
                    confidence REAL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions (session_id) ON DELETE CASCADE,
                    UNIQUE (session_id, address)
                )
                """
            )

            # Index for efficient function name lookups
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_function_names_session
                ON function_names (session_id)
                """
            )
            _ensure_column(conn, "function_names", "status", "TEXT")
            _ensure_column(conn, "function_names", "artifact_id", "TEXT")
            _ensure_column(conn, "function_names", "tool", "TEXT")
            _ensure_column(conn, "function_names", "xref", "TEXT")
            conn.execute(
                """
                UPDATE function_names
                SET status = 'proposed'
                WHERE source = 'llm' AND (status IS NULL OR status = '')
                """
            )
            conn.execute(
                """
                UPDATE function_names
                SET status = 'accepted'
                WHERE source != 'llm' AND (status IS NULL OR status = '')
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proposed_annotations (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    address TEXT,
                    artifact_id TEXT,
                    tool TEXT,
                    xref TEXT,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'proposed',
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions (session_id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_proposed_annotations_session
                ON proposed_annotations (session_id, status)
                """
            )

    def store_proposed_annotations(self, session_id: str, rows: list[dict[str, Any]]) -> int:
        """Insert or refresh LLM proposals. Stable ids so a retry does not fork rows."""
        if not rows:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        stored = 0
        with self.connect() as conn:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                payload = row.get("payload") if isinstance(row.get("payload"), dict) else {"text": row.get("text")}
                ann_id = str(row.get("id") or _annotation_id(session_id, row))
                conn.execute(
                    """
                    INSERT INTO proposed_annotations (
                        id, session_id, kind, address, artifact_id, tool, xref, payload, status, source, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (id) DO UPDATE SET
                        payload = excluded.payload,
                        status = excluded.status,
                        artifact_id = excluded.artifact_id,
                        tool = excluded.tool,
                        xref = excluded.xref,
                        updated_at = excluded.updated_at
                    """,
                    (
                        ann_id,
                        session_id,
                        str(row.get("kind") or "claim"),
                        row.get("address"),
                        row.get("artifact_id") or row.get("artifactId"),
                        row.get("tool"),
                        row.get("xref"),
                        json.dumps(payload),
                        str(row.get("status") or "proposed"),
                        str(row.get("source") or "llm"),
                        now,
                        now,
                    ),
                )
                stored += 1
        return stored

    def iter_actions(self, trajectory_id: str) -> Iterator[sqlite3.Row]:
        with self.connect() as conn:
            yield from conn.execute(
                "SELECT * FROM trajectory_actions WHERE trajectory_id = ? ORDER BY seq",
                (trajectory_id,),
            )
