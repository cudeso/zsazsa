"""Tests for the shared newsletter ingest helper.

    python -m unittest tests.test_newsletter_ingest
"""

import unittest
from unittest import mock

from webapp import newsletter_ingest


class PublishArticles(unittest.TestCase):
    def test_counts_published_and_no_subscriber(self):
        articles = [
            {"url": "http://a", "title": "A", "section": "Malware", "priority": "critical"},
            {"url": "http://b", "title": "B"},
        ]
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=[1, 0]) as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", articles)
        self.assertEqual(pub.call_count, 2)
        self.assertEqual(counts, {"published": 2, "failed": 0, "no_subscriber": 1})

    def test_skips_articles_without_url(self):
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", return_value=1) as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", [{"title": "no url"}])
        pub.assert_not_called()
        self.assertEqual(counts["published"], 0)

    def test_publish_failure_counted(self):
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=OSError("down")):
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", [{"url": "http://a"}])
        self.assertEqual(counts, {"published": 0, "failed": 1, "no_subscriber": 0})

    def test_message_carries_feed_and_section_tags(self):
        captured = {}

        def fake_publish(message):
            captured.update(message)
            return 1

        article = {"url": "http://a", "title": "T", "section": "Vulnerabilities", "priority": "urgent"}
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=fake_publish):
            newsletter_ingest.publish_articles("ETDA CTI Robot", [article])
        self.assertEqual(captured["link"], "http://a")
        self.assertEqual(captured["feed"], "ETDA CTI Robot")
        self.assertIn('zsazsa:newsletter-section="vulnerabilities"', captured["feed_tags"])
        self.assertIn('zsazsa:newsletter-priority="urgent"', captured["feed_tags"])


class ArticlesFromParsed(unittest.TestCase):
    def test_maps_and_drops_urlless(self):
        parsed = {
            "articles": [
                {"primary_url": "http://a", "title": "A", "section": "S", "priority_key": "critical"},
                {"primary_url": "", "title": "no url"},
            ]
        }
        out = newsletter_ingest.articles_from_parsed(parsed)
        self.assertEqual(out, [
            {"url": "http://a", "title": "A", "section": "S", "priority": "critical"},
        ])


if __name__ == "__main__":
    unittest.main()
