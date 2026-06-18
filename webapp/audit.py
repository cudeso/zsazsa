import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

import config
from webapp import misp_session


@contextmanager
def _conn():
    """Yield a SQLite connection that commits on success and always closes."""
    c = sqlite3.connect(config.DB_FILE)
    c.row_factory = sqlite3.Row
    try:
        with c:
            yield c
    finally:
        c.close()


def init():
    os.makedirs(os.path.dirname(config.DB_FILE) or ".", exist_ok=True)
    with _conn() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT,
                entity_label TEXT,
                details TEXT
            )
        """)


def record(action, entity_type, entity_id=None, entity_label=None, details=None):
    with _conn() as db:
        db.execute(
            "INSERT INTO audit_log "
            "(timestamp, user, action, entity_type, entity_id, entity_label, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(timespec="seconds"),
                misp_session.current_user_email(),
                action,
                entity_type,
                entity_id,
                entity_label,
                details,
            ),
        )


def get_logs(limit=200, action=None, entity_type=None):
    with _conn() as db:
        query = "SELECT * FROM audit_log"
        args = []
        where = []

        if action:
            where.append("action = ?")
            args.append(action)
        if entity_type:
            where.append("entity_type = ?")
            args.append(entity_type)

        if where:
            query += " WHERE " + " AND ".join(where)

        query += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return db.execute(query, tuple(args)).fetchall()


def log_filters():
    with _conn() as db:
        actions = [
            r[0] for r in db.execute(
                "SELECT DISTINCT action FROM audit_log ORDER BY action"
            ).fetchall()
        ]
        types = [
            r[0] for r in db.execute(
                "SELECT DISTINCT entity_type FROM audit_log ORDER BY entity_type"
            ).fetchall()
        ]
    return {"actions": actions, "types": types}


def has_event(action, entity_type, entity_id=None, details_contains=None):
    """Return True if at least one matching audit event exists."""
    with _conn() as db:
        query = [
            "SELECT 1 FROM audit_log",
            "WHERE action = ? AND entity_type = ?",
        ]
        args = [action, entity_type]

        if entity_id is not None:
            query.append("AND entity_id = ?")
            args.append(entity_id)
        if details_contains:
            query.append("AND details LIKE ?")
            args.append(f"%{details_contains}%")

        query.append("LIMIT 1")
        row = db.execute(" ".join(query), tuple(args)).fetchone()
        return row is not None


def latest_event(action, entity_type, entity_id=None):
    """Return the latest matching audit row, or None."""
    with _conn() as db:
        query = [
            "SELECT * FROM audit_log",
            "WHERE action = ? AND entity_type = ?",
        ]
        args = [action, entity_type]
        if entity_id is not None:
            query.append("AND entity_id = ?")
            args.append(entity_id)
        query.append("ORDER BY id DESC LIMIT 1")
        return db.execute(" ".join(query), tuple(args)).fetchone()
