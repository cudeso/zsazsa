"""Test create_newsletter_event archives the raw e-mail, tags, and URLs.

Stubs _misp and _tag_local so it runs offline.

    python -m unittest tests.test_misp_store_newsletter
"""

import unittest
from types import SimpleNamespace

from webapp import misp_store


class FakeMisp:
    def __init__(self):
        self.reports = []
        self.attributes = []

    def add_event(self, event, pythonify=True):
        self.event = event
        return SimpleNamespace(uuid="new-uuid", id=42)

    def add_event_report(self, event_id, report):
        self.reports.append((event_id, report))

    def add_attribute(self, event_id, attr):
        self.attributes.append((event_id, attr))


class CreateNewsletterEvent(unittest.TestCase):
    def setUp(self):
        self.fake = FakeMisp()
        self.tags = []
        self._orig_misp = misp_store._misp
        self._orig_tag = misp_store._tag_local
        misp_store._misp = lambda: self.fake
        misp_store._tag_local = lambda misp, uuid, name: self.tags.append(name)

    def tearDown(self):
        misp_store._misp = self._orig_misp
        misp_store._tag_local = self._orig_tag

    def test_archives_email_tags_and_urls(self):
        uuid = misp_store.create_newsletter_event(
            "ETDA CTI Robot", "raw e-mail body",
            report_title="ETDA CTI 21 May", tlp="green",
            article_urls=["https://a.example", "https://b.example"],
        )
        self.assertEqual(uuid, "new-uuid")
        self.assertIn('zsazsa:source-type="newsletter"', self.tags)
        self.assertIn('zsazsa:source="etda-cti-robot"', self.tags)

        self.assertEqual(len(self.fake.reports), 1)
        _eid, report = self.fake.reports[0]
        self.assertEqual(report.content, "raw e-mail body")
        self.assertIn("ETDA CTI Robot", report.name)

        urls = [attr.value for _eid, attr in self.fake.attributes]
        self.assertEqual(urls, ["https://a.example", "https://b.example"])
        self.assertTrue(all(attr.type == "link" for _eid, attr in self.fake.attributes))

    def test_parser_recorded_as_tag(self):
        misp_store.create_newsletter_event(
            "ETDA", "body", parser="ETDA CTI Robot",
        )
        self.assertIn('zsazsa:newsletter-parser="ETDA CTI Robot"', self.tags)
        self.assertIn('zsazsa:source="etda"', self.tags)

    def test_reliability_applies_admiralty_tag(self):
        misp_store.create_newsletter_event(
            "ETDA CTI Robot", "body", tlp="green", reliability="b",
        )
        tag_names = [t.name for t in self.fake.event.tags]
        self.assertIn('admiralty-scale:source-reliability="b"', tag_names)

    def test_unrated_adds_no_admiralty_tag(self):
        misp_store.create_newsletter_event("ETDA CTI Robot", "body", reliability="")
        tag_names = [t.name for t in self.fake.event.tags]
        self.assertFalse(any("admiralty-scale" in n for n in tag_names))

    def test_no_report_when_email_blank(self):
        misp_store.create_newsletter_event("ETDA CTI Robot", "   ", article_urls=[])
        self.assertEqual(self.fake.reports, [])
        self.assertEqual(self.fake.attributes, [])


class ReviewFakeMisp:
    def __init__(self, tag_names, report_name, content="raw"):
        self.event = SimpleNamespace(
            id=42,
            tags=[SimpleNamespace(name=n) for n in tag_names],
        )
        self._reports = [SimpleNamespace(name=report_name, content=content)]

    def get_event(self, uuid, pythonify=True):
        return self.event

    def get_event_reports(self, event_id, pythonify=True):
        return self._reports


class GetNewsletterForReview(unittest.TestCase):
    def _run(self, fake):
        orig = misp_store._misp
        misp_store._misp = lambda: fake
        try:
            return misp_store.get_newsletter_for_review("some-uuid")
        finally:
            misp_store._misp = orig

    def test_recovers_feed_and_parser(self):
        fake = ReviewFakeMisp(
            ['zsazsa:newsletter-parser="ETDA CTI Robot"'],
            "Newsletter source: ETDA",
        )
        item = self._run(fake)
        self.assertEqual(item["feed"], "ETDA")
        self.assertEqual(item["parser"], "ETDA CTI Robot")

    def test_legacy_without_parser_tag_falls_back_to_feed(self):
        fake = ReviewFakeMisp([], "Newsletter source: ETDA CTI Robot")
        item = self._run(fake)
        self.assertEqual(item["feed"], "ETDA CTI Robot")
        self.assertEqual(item["parser"], "ETDA CTI Robot")


if __name__ == "__main__":
    unittest.main()
