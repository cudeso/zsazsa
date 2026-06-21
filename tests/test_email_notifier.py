"""Tests for the email notifier.

Verifies recipient resolution from email channels and that send_email builds a
multipart message and delivers it over a (mocked) SMTP connection.

    python -m unittest tests.test_email_notifier
"""

import unittest
from types import SimpleNamespace
from unittest import mock

import config
from notifier import email


class Recipients(unittest.TestCase):
    def setUp(self):
        self._orig = config.NOTIFICATION_CHANNELS
        config.NOTIFICATION_CHANNELS = [
            {"id": "mm1", "name": "MM", "type": "mattermost", "url": "x", "enabled": True},
            {"id": "em1", "name": "SOC", "type": "email", "recipient": "soc@x.test", "enabled": True},
            {"id": "em2", "name": "Off", "type": "email", "recipient": "off@x.test", "enabled": False},
            {"id": "em3", "name": "Dup", "type": "email", "recipient": "soc@x.test", "enabled": True},
        ]

    def tearDown(self):
        config.NOTIFICATION_CHANNELS = self._orig

    def test_only_enabled_email_channels(self):
        self.assertEqual(email._recipients(), ["soc@x.test"])

    def test_filter_by_channel_ids(self):
        self.assertEqual(email._recipients(["em1"]), ["soc@x.test"])
        self.assertEqual(email._recipients(["mm1"]), [])

    def test_ignores_mattermost_and_disabled(self):
        self.assertEqual(email._recipients(["em2"]), [])


class SendEmail(unittest.TestCase):
    def setUp(self):
        self._orig_attrs = {
            k: getattr(config, k, None)
            for k in ("SMTP_HOST", "SMTP_PORT", "SMTP_USE_TLS", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM")
        }
        config.SMTP_HOST = "smtp.test"
        config.SMTP_PORT = 587
        config.SMTP_USE_TLS = True
        config.SMTP_USERNAME = "user"
        config.SMTP_PASSWORD = "pw"
        config.SMTP_FROM = "cti@x.test"

    def tearDown(self):
        for k, v in self._orig_attrs.items():
            setattr(config, k, v)

    def test_no_recipients_returns_false(self):
        with mock.patch("notifier.email.smtplib.SMTP") as smtp:
            self.assertFalse(email.send_email([], "s", "body", "label"))
            smtp.assert_not_called()

    def test_missing_host_returns_false(self):
        config.SMTP_HOST = ""
        with mock.patch("notifier.email.smtplib.SMTP") as smtp:
            self.assertFalse(email.send_email(["a@x.test"], "s", "body", "label"))
            smtp.assert_not_called()

    def test_sends_multipart_with_starttls_and_login(self):
        with mock.patch("notifier.email.smtplib.SMTP") as smtp:
            server = smtp.return_value.__enter__.return_value
            ok = email.send_email(["a@x.test"], "Subject", "# Hello", "label")

        self.assertTrue(ok)
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("user", "pw")
        msg = server.send_message.call_args.args[0]
        self.assertEqual(msg["Subject"], "Subject")
        self.assertEqual(msg["From"], "cti@x.test")
        self.assertEqual(msg["To"], "a@x.test")
        self.assertTrue(msg.is_multipart())
        subtypes = {p.get_content_subtype() for p in msg.iter_parts()}
        self.assertEqual(subtypes, {"plain", "html"})

    def test_multiple_recipients_are_hidden_from_each_other(self):
        recipients = ["a@x.test", "b@x.test"]
        with mock.patch("notifier.email.smtplib.SMTP") as smtp:
            server = smtp.return_value.__enter__.return_value
            email.send_email(recipients, "Subject", "body", "label")
        msg = server.send_message.call_args.args[0]
        # Addresses are not exposed in the visible To header...
        self.assertEqual(msg["To"], "cti@x.test")
        # ...but delivery still goes to every recipient.
        self.assertEqual(server.send_message.call_args.kwargs["to_addrs"], recipients)

    def test_smtp_error_returns_false(self):
        import smtplib

        with mock.patch("notifier.email.smtplib.SMTP", side_effect=smtplib.SMTPException("boom")):
            self.assertFalse(email.send_email(["a@x.test"], "s", "body", "label"))


class TestConnection(unittest.TestCase):
    def test_missing_host(self):
        self.assertFalse(email.test_connection("", 587, True, "", "")["ok"])

    def test_success_with_tls_and_login(self):
        with mock.patch("notifier.email.smtplib.SMTP") as smtp:
            server = smtp.return_value.__enter__.return_value
            result = email.test_connection("smtp.test", 587, True, "user", "pw")
        self.assertTrue(result["ok"])
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("user", "pw")

    def test_no_login_when_username_empty(self):
        with mock.patch("notifier.email.smtplib.SMTP") as smtp:
            server = smtp.return_value.__enter__.return_value
            email.test_connection("smtp.test", 25, False, "", "")
        server.starttls.assert_not_called()
        server.login.assert_not_called()

    def test_failure_returns_error(self):
        import smtplib

        with mock.patch("notifier.email.smtplib.SMTP",
                        side_effect=smtplib.SMTPAuthenticationError(535, b"bad")):
            result = email.test_connection("smtp.test", 587, True, "user", "wrong")
        self.assertFalse(result["ok"])
        self.assertTrue(result["error"])


class ProductSenders(unittest.TestCase):
    """The product markdown already carries its own preview link, so the senders
    must pass it through unchanged (no duplicated link) and only set the subject."""

    def test_pir_passes_markdown_through_unchanged(self):
        pir = SimpleNamespace(pir_id="PIR-001", question="What is the threat?")
        md = "# PIR\n\nbody\n\n[Open PIR preview](http://x/p)"
        with mock.patch("notifier.email.send_email", return_value=True) as send:
            email.send_pir_notification(pir, md, channel_ids=["em1"])
        _, subject, body, _ = send.call_args.args
        self.assertEqual(body, md)
        self.assertIn("PIR-001", subject)

    def test_vea_subject_includes_cve_and_title(self):
        vea = SimpleNamespace(vea_id="VEA-9", cve_id="CVE-2026-1", title="RCE")
        with mock.patch("notifier.email.send_email", return_value=True) as send:
            email.send_vea_notification(vea, "body")
        subject = send.call_args.args[1]
        self.assertIn("VEA-9", subject)
        self.assertIn("CVE-2026-1", subject)
        self.assertIn("RCE", subject)


if __name__ == "__main__":
    unittest.main()
