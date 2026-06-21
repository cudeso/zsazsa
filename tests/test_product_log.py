"""Tests for product source logging (webapp.product_log).

Monkeypatches the cache lookup and log_event so it runs offline.

    python -m unittest tests.test_product_log
"""

import unittest

from webapp import product_log

_FAKE_ROWS = [
    {"uuid": "u1", "info": "Event one", "tags": ["scraper:data-collection-source:ETDA CTI Robot"]},
    {"uuid": "u2", "info": "Event two", "tags": ["tlp:clear"]},
]


class LogProductSources(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._orig_log = product_log.log_event
        self._orig_get = product_log.collection_cache.get_events_by_uuids
        product_log.log_event = lambda **kw: self.calls.append(kw)
        product_log.collection_cache.get_events_by_uuids = lambda uuids: [
            r for r in _FAKE_ROWS if r["uuid"] in uuids
        ]

    def tearDown(self):
        product_log.log_event = self._orig_log
        product_log.collection_cache.get_events_by_uuids = self._orig_get

    def test_logs_each_source_with_resolved_feed(self):
        product_log.log_product_sources(["u1", "u2"], "flash-intel")
        self.assertEqual(len(self.calls), 2)
        c1 = next(c for c in self.calls if c["event_uuid"] == "u1")
        self.assertEqual(c1["source_feed"], "ETDA CTI Robot")
        self.assertEqual(c1["outcome"], "product_created")
        self.assertEqual(c1["detail"], "flash-intel")
        self.assertEqual(c1["event_info"], "Event one")
        c2 = next(c for c in self.calls if c["event_uuid"] == "u2")
        self.assertEqual(c2["source_feed"], "unknown")

    def test_dedups_and_skips_blanks(self):
        product_log.log_product_sources(["u1", "u1", "", None], "vea")
        self.assertEqual([c["event_uuid"] for c in self.calls], ["u1"])

    def test_empty_input_does_nothing(self):
        product_log.log_product_sources([], "vea")
        product_log.log_product_sources(None, "vea")
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
