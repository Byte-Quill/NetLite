"""SQLite persistence for diagnostic history.

The database is deliberately lightweight:

* one table, ``history``, with a small fixed schema;
* connection-per-call (no long-lived threads or connection pooling);
* WAL journal mode for concurrent reads while writing;
* automatic retention so the table never grows without bound.

No sensitive payloads are ever stored -- only a short status summary.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tool       TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    status     TEXT    NOT NULL,
    timestamp  TEXT    NOT NULL,
    summary    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history (timestamp DESC);
"""


def connect(path: Path) -> sqlite3.Connection:
    """Open a new SQLite connection to ``path`` (creating it if needed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def session(path: Path) -> Iterator[sqlite3.Connection]:
    """Context manager yielding a connection, committing on success."""
    conn = connect(path)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()
    finally:
        conn.close()


def add_history(
    path: Path,
    tool: str,
    target: str,
    status: str,
    summary: str,
    timestamp: str,
) -> int:
    """Insert one history record and return its id."""
    with session(path) as conn:
        cur = conn.execute(
            "INSERT INTO history (tool, target, status, timestamp, summary) "
            "VALUES (?, ?, ?, ?, ?)",
            (tool, target[:255], status, timestamp, summary[:500]),
        )
        return int(cur.lastrowid)


def list_history(path: Path, limit: int = 100) -> list[dict]:
    """Return up to ``limit`` recent records, newest first."""
    with session(path) as conn:
        rows = conn.execute(
            "SELECT id, tool, target, status, timestamp, summary "
            "FROM history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def delete_history(path: Path, record_id: int) -> bool:
    """Delete a single record; returns True if a row was removed."""
    with session(path) as conn:
        cur = conn.execute("DELETE FROM history WHERE id = ?", (record_id,))
        return cur.rowcount == 1


def prune_history(path: Path, max_records: int) -> int:
    """Delete the oldest records beyond ``max_records``; return count removed."""
    with session(path) as conn:
        cur = conn.execute(
            "DELETE FROM history WHERE id NOT IN ("
            "  SELECT id FROM history ORDER BY id DESC LIMIT ?"
            ")",
            (max_records,),
        )
        return cur.rowcount