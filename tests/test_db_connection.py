"""Tests for the SQLite connection contextmanager (batch 1).

Confirms the _connect() helper commits on success, rolls back on error, and
always closes the connection (no leaked handles).

    python -m unittest tests.test_db_connection
"""

import os
import sqlite3
import tempfile
import unittest

import config
from core import db


class ConnectContextManager(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self._orig = config.DB_FILE
        config.DB_FILE = self._tmp.name
        with db._connect() as conn:
            conn.execute("CREATE TABLE t (x INTEGER)")

    def tearDown(self):
        config.DB_FILE = self._orig
        os.unlink(self._tmp.name)

    def test_commits_on_success(self):
        with db._connect() as conn:
            conn.execute("INSERT INTO t VALUES (1)")
        with db._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM t").fetchone()[0], 1)

    def test_rolls_back_on_error(self):
        with self.assertRaises(RuntimeError):
            with db._connect() as conn:
                conn.execute("INSERT INTO t VALUES (2)")
                raise RuntimeError("boom")
        with db._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM t").fetchone()[0], 0)

    def test_connection_is_closed_after_use(self):
        with db._connect() as conn:
            conn.execute("SELECT 1")
        # Operating on a closed connection raises; this proves the finally-close ran.
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
