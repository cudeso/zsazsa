"""Tests for the /api/fetch-url SSRF guard (batch 1).

Uses IP-literal and localhost URLs so getaddrinfo resolves without network
access, keeping the tests deterministic and offline.

    python -m unittest tests.test_api_ssrf
"""

import unittest

from webapp.routes.api import _is_safe_public_url


class SafePublicUrl(unittest.TestCase):
    def test_rejects_loopback_and_internal(self):
        for url in [
            "http://127.0.0.1/",
            "http://127.0.0.1:6379/",
            "http://localhost/",
            "http://10.0.0.5/",
            "http://192.168.1.10/",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/",
            "http://[::1]/",
        ]:
            self.assertFalse(_is_safe_public_url(url), url)

    def test_rejects_non_http_schemes(self):
        for url in ["file:///etc/passwd", "gopher://x/", "ftp://example.com/", "data:text/plain,hi"]:
            self.assertFalse(_is_safe_public_url(url), url)

    def test_rejects_empty_or_garbage(self):
        for url in ["", "not a url", "http://"]:
            self.assertFalse(_is_safe_public_url(url), url)

    def test_allows_public_ip_literals(self):
        self.assertTrue(_is_safe_public_url("https://8.8.8.8/"))
        self.assertTrue(_is_safe_public_url("http://1.1.1.1/"))


if __name__ == "__main__":
    unittest.main()
