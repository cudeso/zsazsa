"""Tests for the ETDA CTI Robot newsletter parser.

    python -m unittest tests.test_newsletter_parsers
"""

import unittest

from webapp import newsletter_parsers

SAMPLE = """\
Report
[FIRST] ETDA Cyber Threat Intelligence 21 May 2026

Quick overview:
Critical\tUrgent\tImportant
Financial Sector\t0\t0\t1
Industrial Sector\t1\t2\t0
Vulnerabilities\t1\t0\t0
Financial Sector

2026 Report: Industrialized Attacks Target Financial Services

"The financial services industry has a visibility gap."
Priority: 3 - Important
Relevance: General, Trends and statistics

<https://www.akamai.com/lp/soti/financial-services-security-trends>
<https://www.bankinfosecurity.com/ai-botnets-a-31730>
↑
Industrial Sector

Siemens RUGGEDCOM APE1808 Devices

"A buffer overflow vulnerability allows code execution."
Priority: 1 - Critical
Relevance: General

<https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02>
ScadaBR

"Unauthenticated remote code execution."
Priority: 2 - Urgent
Relevance: General

<https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-03>
↑
Vulnerabilities

Drupal Core - Highly Critical - SQL Injection - SA-CORE-2026-004

"A vulnerability in the database API allows SQL injection."
Priority: 1 - Critical
Relevance: General

<https://www.drupal.org/sa-core-2026-004>
↑
TLP: GREEN
"""


class ParseEtda(unittest.TestCase):
    def setUp(self):
        self.result = newsletter_parsers.parse("ETDA CTI Robot", SAMPLE)
        self.articles = self.result["articles"]
        self.by_title = {a["title"]: a for a in self.articles}

    def test_report_metadata(self):
        self.assertIn("ETDA Cyber Threat Intelligence", self.result["report_title"])
        self.assertEqual(self.result["tlp"], "green")

    def test_all_articles_found(self):
        self.assertEqual(len(self.articles), 4)

    def test_sections_assigned(self):
        self.assertEqual(self.by_title["ScadaBR"]["section"], "Industrial Sector")
        self.assertEqual(
            self.by_title["2026 Report: Industrialized Attacks Target Financial Services"]["section"],
            "Financial Sector",
        )

    def test_priority_mapping(self):
        self.assertEqual(self.by_title["Siemens RUGGEDCOM APE1808 Devices"]["priority_key"], "critical")
        self.assertEqual(self.by_title["ScadaBR"]["priority_key"], "urgent")

    def test_primary_and_related_urls(self):
        fin = self.by_title["2026 Report: Industrialized Attacks Target Financial Services"]
        self.assertEqual(fin["primary_url"], "https://www.akamai.com/lp/soti/financial-services-security-trends")
        self.assertEqual(fin["related_urls"], ["https://www.bankinfosecurity.com/ai-botnets-a-31730"])

    def test_intro_captured_without_quotes(self):
        siemens = self.by_title["Siemens RUGGEDCOM APE1808 Devices"]
        self.assertEqual(siemens["intro"], "A buffer overflow vulnerability allows code execution.")

    def test_title_with_dashes_kept_intact(self):
        self.assertIn("Drupal Core - Highly Critical - SQL Injection - SA-CORE-2026-004", self.by_title)

    def test_unknown_source_raises(self):
        with self.assertRaises(ValueError):
            newsletter_parsers.parse("Nope", SAMPLE)


if __name__ == "__main__":
    unittest.main()
