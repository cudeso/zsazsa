"""Tests for analyser.tagger source-feed extraction.

    python -m unittest tests.test_tagger
"""

import unittest
from types import SimpleNamespace

from analyser import tagger


class SourceFeed(unittest.TestCase):
    def test_from_tag_names(self):
        tags = ['tlp:clear', 'scraper:data-collection-source:ETDA CTI Robot', 'workflow:state="complete"']
        self.assertEqual(tagger.source_feed_from_tags(tags), "ETDA CTI Robot")

    def test_unknown_when_absent(self):
        self.assertEqual(tagger.source_feed_from_tags(['tlp:clear']), "unknown")
        self.assertEqual(tagger.source_feed_from_tags([]), "unknown")
        self.assertEqual(tagger.source_feed_from_tags(None), "unknown")

    def test_get_source_feed_reads_tag_objects(self):
        event = SimpleNamespace(tags=[
            SimpleNamespace(name="tlp:green"),
            SimpleNamespace(name="scraper:data-collection-source:HackerNews"),
        ])
        self.assertEqual(tagger.get_source_feed(event), "HackerNews")


if __name__ == "__main__":
    unittest.main()
