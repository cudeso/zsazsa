"""Tests for the shared product list sorter.

    python -m unittest tests.test_sort_products
"""

import unittest
from datetime import datetime
from types import SimpleNamespace

from webapp.utils import sort_products


def _p(title, state, published_at, date=""):
    return SimpleNamespace(title=title, review_state=state, published_at=published_at, date=date)


class SortProducts(unittest.TestCase):
    def test_title_case_insensitive(self):
        items = [_p("banana", "draft", None), _p("Apple", "approved", None)]
        self.assertEqual([p.title for p in sort_products(items, "title", "asc")], ["Apple", "banana"])

    def test_state(self):
        items = [_p("a", "draft", None), _p("b", "approved", None)]
        self.assertEqual([p.review_state for p in sort_products(items, "state", "asc")],
                         ["approved", "draft"])

    def test_date_handles_none_alongside_datetimes(self):
        # Regression: a published date and an unpublished None must sort without error.
        items = [
            _p("a", "draft", None),
            _p("b", "approved", datetime(2026, 6, 1, 12, 0)),
            _p("c", "approved", datetime(2026, 1, 1, 9, 0)),
        ]
        ordered = sort_products(items, "date", "desc")
        self.assertEqual([p.title for p in ordered], ["b", "c", "a"])

    def test_briefing_date_key(self):
        items = [_p("a", "published", None, date="2026-02-01"),
                 _p("b", "published", None, date="2026-01-01")]
        self.assertEqual([p.date for p in sort_products(items, "bdate", "asc")],
                         ["2026-01-01", "2026-02-01"])

    def test_unknown_key_keeps_order(self):
        items = [_p("z", "draft", None), _p("a", "draft", None)]
        self.assertEqual([p.title for p in sort_products(items, "whatever", "asc")], ["z", "a"])


if __name__ == "__main__":
    unittest.main()
