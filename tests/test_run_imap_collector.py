"""Tests for the IMAP collector runner's source-selection logic.

    python -m unittest tests.test_run_imap_collector
"""

import email
import unittest

import run_imap_collector


def _msg(subject: str, sender: str):
    return email.message_from_string(f"Subject: {subject}\nFrom: {sender}\n\nbody")


class MatchSource(unittest.TestCase):
    def setUp(self):
        self.sources = [
            {"name": "ETDA", "subjects": ["etda"], "senders": []},
            {"name": "Weekly", "subjects": [], "senders": ["weekly@vendor.com"]},
        ]

    def test_matches_by_subject(self):
        s = run_imap_collector._match_source(_msg("Fwd: ETDA digest", "a@b.c"), self.sources)
        self.assertEqual(s["name"], "ETDA")

    def test_matches_by_sender(self):
        s = run_imap_collector._match_source(_msg("anything", "weekly@vendor.com"), self.sources)
        self.assertEqual(s["name"], "Weekly")

    def test_no_match_returns_none(self):
        self.assertIsNone(run_imap_collector._match_source(_msg("sales", "x@y.z"), self.sources))

    def test_first_matching_source_wins(self):
        # A catch-all source (no criteria) placed first takes every message.
        sources = [{"name": "All", "subjects": [], "senders": []}] + self.sources
        s = run_imap_collector._match_source(_msg("Fwd: ETDA digest", "a@b.c"), sources)
        self.assertEqual(s["name"], "All")


if __name__ == "__main__":
    unittest.main()
