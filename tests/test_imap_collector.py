"""Tests for the IMAP newsletter collector's pure parsing and matching logic.

    python -m unittest tests.test_imap_collector
"""

import email
import unittest

from core import imap_collector


def _msg(headers: dict, body: str, subtype: str = "plain") -> email.message.Message:
    raw = "".join(f"{k}: {v}\n" for k, v in headers.items())
    raw += f"Content-Type: text/{subtype}; charset=utf-8\n\n{body}"
    return email.message_from_string(raw)


class ExtractBody(unittest.TestCase):
    def test_plain_text(self):
        m = _msg({"Subject": "Hi"}, "Line one\nLine two")
        self.assertEqual(imap_collector.extract_body(m), "Line one\nLine two")

    def test_html_fallback_to_text(self):
        m = _msg({"Subject": "Hi"}, "<p>Hello <b>world</b></p>", subtype="html")
        body = imap_collector.extract_body(m)
        self.assertIn("Hello", body)
        self.assertNotIn("<p>", body)

    def test_prefers_plain_over_html_in_multipart(self):
        raw = (
            "Subject: Multi\n"
            'Content-Type: multipart/alternative; boundary="b"\n\n'
            "--b\nContent-Type: text/plain; charset=utf-8\n\nPLAIN body\n"
            "--b\nContent-Type: text/html; charset=utf-8\n\n<p>HTML body</p>\n"
            "--b--\n"
        )
        m = email.message_from_string(raw)
        self.assertEqual(imap_collector.extract_body(m).strip(), "PLAIN body")

    def test_strips_gmail_forward_preamble(self):
        body = (
            "---------- Forwarded message ----------\n"
            "From: ETDA <no-reply@etda.or.th>\n"
            "Date: Tue, 1 Jan 2026\n"
            "Subject: CTI Robot\n"
            "To: me@gmail.com\n"
            "\n"
            "Actual newsletter content starts here"
        )
        m = _msg({"Subject": "Fwd: CTI Robot"}, body)
        self.assertEqual(imap_collector.extract_body(m), "Actual newsletter content starts here")

    def test_skips_attachments(self):
        raw = (
            "Subject: WithAttach\n"
            'Content-Type: multipart/mixed; boundary="b"\n\n'
            "--b\nContent-Type: text/plain; charset=utf-8\n\nReal body\n"
            "--b\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=x.pdf\n\nJVBERi0=\n"
            "--b--\n"
        )
        m = email.message_from_string(raw)
        self.assertEqual(imap_collector.extract_body(m).strip(), "Real body")


class Matching(unittest.TestCase):
    def test_subject_match(self):
        m = _msg({"Subject": "Fwd: ETDA CTI Robot", "From": "me@gmail.com"}, "body")
        self.assertTrue(imap_collector.matches(m, ["cti robot"], []))

    def test_sender_match_on_header(self):
        m = _msg({"Subject": "x", "From": "ETDA <no-reply@etda.or.th>"}, "body")
        self.assertTrue(imap_collector.matches(m, [], ["etda.or.th"]))

    def test_sender_match_on_forwarded_original(self):
        # The envelope From is the forwarder; the real sender is in the forwarded
        # preamble, which matching must still see even though parsing strips it.
        body = (
            "---------- Forwarded message ----------\n"
            "From: ETDA <no-reply@etda.or.th>\n"
            "Subject: CTI Robot\n\n"
            "newsletter content"
        )
        m = _msg({"Subject": "Fwd", "From": "me@gmail.com"}, body)
        self.assertTrue(imap_collector.matches(m, [], ["no-reply@etda.or.th"]))
        # And the body handed to the parser has the preamble removed.
        self.assertEqual(imap_collector.extract_body(m), "newsletter content")

    def test_sender_match_on_apple_quoted_forward(self):
        # Apple Mail forwards quote every line with "> "; the original sender
        # still has to be found despite the quote marker.
        body = (
            "> Begin forwarded message:\n"
            "> From: ETDA <no-reply@etda.or.th>\n"
            "> Subject: CTI Robot\n>\n"
            "> newsletter content"
        )
        m = _msg({"Subject": "Fwd", "From": "me@gmail.com"}, body)
        self.assertTrue(imap_collector.matches(m, [], ["no-reply@etda.or.th"]))

    def test_no_criteria_matches_all(self):
        m = _msg({"Subject": "anything", "From": "a@b.c"}, "body")
        self.assertTrue(imap_collector.matches(m, [], []))
        # blank entries count as no criteria too
        self.assertTrue(imap_collector.matches(m, ["", "  "], []))

    def test_no_match(self):
        m = _msg({"Subject": "weekly sales", "From": "sales@shop.com"}, "body")
        self.assertFalse(imap_collector.matches(m, ["etda"], ["etda.or.th"]))


if __name__ == "__main__":
    unittest.main()
