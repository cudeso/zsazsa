"""Tests for the shared notify-status badge helper used by all product pages.

    python -m unittest tests.test_audit_notify_status
"""

import unittest
from unittest import mock

from webapp import audit


class LatestNotifyStatus(unittest.TestCase):
    def _status(self, details):
        row = {"details": details, "timestamp": "2026-06-22T00:00:00"}
        with mock.patch.object(audit, "latest_event", return_value=row):
            return audit.latest_notify_status("fia", "x")

    def test_delivered(self):
        self.assertEqual(self._status("publish notification; result=ok")["tone"], "success")
        self.assertEqual(self._status("publish notification; result=ok")["label"], "Delivered")

    def test_failed(self):
        self.assertEqual(self._status("publish notification; result=failed")["label"], "Failed")

    def test_skipped(self):
        self.assertEqual(self._status("skipped types: email")["label"], "Skipped")

    def test_unknown(self):
        self.assertEqual(self._status("queued for later")["label"], "Unknown")

    def test_none_when_no_event(self):
        with mock.patch.object(audit, "latest_event", return_value=None):
            self.assertIsNone(audit.latest_notify_status("fia", "x"))


if __name__ == "__main__":
    unittest.main()
