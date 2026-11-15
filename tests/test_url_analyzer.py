import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from security.url_analyzer import analyze_url, analyze_urls


class TestUrlAnalyzer(unittest.TestCase):
    def test_https_safe_url_low_risk(self):
        f = analyze_url("https://www.example.com/page")
        self.assertTrue(f.is_https)
        self.assertLess(f.risk_points, 20)

    def test_ip_address_url_flagged(self):
        f = analyze_url("http://192.168.1.5/login")
        self.assertTrue(f.is_ip_address)
        self.assertGreater(f.risk_points, 20)

    def test_at_symbol_flagged(self):
        f = analyze_url("http://example.com@evil.com/login")
        self.assertTrue(f.has_at_symbol)

    def test_shortened_url_flagged(self):
        f = analyze_url("http://bit.ly/abcd123")
        self.assertTrue(f.is_shortened)

    def test_suspicious_tld_flagged(self):
        f = analyze_url("http://secure-login.tk/verify")
        self.assertTrue(f.suspicious_tld)

    def test_lookalike_brand_domain(self):
        f = analyze_url("http://paypal-secure-verify.tk/login")
        self.assertTrue(f.lookalike_suspected)

    def test_analyze_urls_empty_list(self):
        summary = analyze_urls([])
        self.assertEqual(summary["count"], 0)

    def test_analyze_urls_summary_fields(self):
        summary = analyze_urls(["https://example.com", "http://192.168.1.5/x"])
        self.assertEqual(summary["count"], 2)
        self.assertGreaterEqual(summary["max_risk"], summary["avg_risk"])


if __name__ == "__main__":
    unittest.main()
