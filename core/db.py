import sqlite3
import logging
from pathlib import Path

import config

logger = logging.getLogger(__name__)


def _connect():
    return sqlite3.connect(config.DB_FILE)


def init_db() -> None:
    Path(config.DB_FILE).parent.mkdir(exist_ok=True)
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS event_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_uuid   TEXT NOT NULL,
                event_info   TEXT,
                source_feed  TEXT,
                outcome      TEXT,
                detail       TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS llm_usage (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                called_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
                feature          TEXT NOT NULL,
                model            TEXT NOT NULL,
                input_tokens     INTEGER NOT NULL DEFAULT 0,
                output_tokens    INTEGER NOT NULL DEFAULT 0,
                total_tokens     INTEGER NOT NULL DEFAULT 0
            )
        """)


def log_llm_usage(feature: str, model: str, input_tokens: int, output_tokens: int, total_tokens: int) -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO llm_usage (feature, model, input_tokens, output_tokens, total_tokens) VALUES (?, ?, ?, ?, ?)",
                (feature, model, input_tokens, output_tokens, total_tokens),
            )
    except sqlite3.Error as e:
        logger.error("DB write failed for llm_usage: %s", e)


def log_event(event_uuid: str, event_info: str, source_feed: str, outcome: str, detail: str | None = None) -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO event_log (event_uuid, event_info, source_feed, outcome, detail) VALUES (?, ?, ?, ?, ?)",
                (event_uuid, event_info, source_feed, outcome, detail),
            )
    except sqlite3.Error as e:
        logger.error("DB write failed for %s: %s", event_uuid, e)
