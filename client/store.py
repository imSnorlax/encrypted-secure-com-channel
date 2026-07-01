"""
Local session store — SQLite-backed, stores ratchet state per peer.

Schema:
  sessions(peer TEXT PK, ratchet_json TEXT, is_initiator INT, created_at TEXT)

Ratchet state is serialised to JSON (see RatchetState.to_dict).
The DB file lives at ~/.channel/<username>/store.db
"""

import sqlite3
import json
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from .crypto.double_ratchet import RatchetState


def _db_path(username: str) -> Path:
    p = Path.home() / ".channel" / username / "store.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _connect(username: str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path(username)))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            peer         TEXT PRIMARY KEY,
            ratchet_json TEXT NOT NULL,
            is_initiator INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


class SessionStore:
    def __init__(self, username: str) -> None:
        self.username = username
        self._conn = _connect(username)

    def save_session(
        self,
        peer: str,
        state: RatchetState,
        is_initiator: bool = True,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            INSERT INTO sessions (peer, ratchet_json, is_initiator, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(peer) DO UPDATE SET
                ratchet_json = excluded.ratchet_json
            """,
            (peer, json.dumps(state.to_dict()), int(is_initiator), now),
        )
        self._conn.commit()

    def load_session(self, peer: str) -> Optional[RatchetState]:
        row = self._conn.execute(
            "SELECT ratchet_json FROM sessions WHERE peer = ?", (peer,)
        ).fetchone()
        if row is None:
            return None
        return RatchetState.from_dict(json.loads(row["ratchet_json"]))

    def has_session(self, peer: str) -> bool:
        return self.load_session(peer) is not None

    def list_sessions(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT peer FROM sessions ORDER BY created_at"
        ).fetchall()
        return [r["peer"] for r in rows]

    def delete_session(self, peer: str) -> None:
        self._conn.execute("DELETE FROM sessions WHERE peer = ?", (peer,))
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
