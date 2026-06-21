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


if __name__ == "__main__":
    unittest.main()
