"""SQLite-backed store for incidents (grouped alerts)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .rule_engine import Incident

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    rule TEXT NOT NULL,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    severity TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen);
"""


class AlertStore:
    def __init__(self, db_path: str | Path = "iotsentinel.db"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def upsert_incident(self, incident: Incident) -> None:
        self.upsert_incidents([incident])

    def upsert_incidents(self, incidents) -> None:
        self._conn.executemany(
            """
            INSERT INTO incidents (id, rule, source, target, severity, first_seen, last_seen, count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                severity=excluded.severity,
                last_seen=excluded.last_seen,
                count=excluded.count
            """,
            [(i.id, i.rule, i.source, i.target, i.severity, i.first_seen, i.last_seen, i.count)
             for i in incidents],
        )
        self._conn.commit()

    def recent(self, limit: int = 200) -> list[dict]:
        cur = self._conn.execute(
            "SELECT id, rule, source, target, severity, first_seen, last_seen, count "
            "FROM incidents ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    def clear(self) -> None:
        """Delete every stored incident, leaving the schema in place.

        The dashboard's Reset button uses this. Without it a reset only
        cleared the in-memory session, while the database kept incidents
        from previous runs, so the alert log never actually emptied.
        """
        self._conn.execute("DELETE FROM incidents")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
