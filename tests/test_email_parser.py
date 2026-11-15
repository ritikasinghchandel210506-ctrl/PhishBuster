import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.email_parser import parse_eml_bytes, parse_manual_email, EmailParseError


class TestEmailParser(unittest.TestCase):
    def test_parse_manual_email_basic(self):
        parsed = parse_manual_email("Alice <alice@example.com>", "bob@example.com",
                                     "Hello", "This is a test body with a link http://example.com")
        self.assertEqual(parsed.sender_email, "alice@example.com")
        self.assertEqual(parsed.subject, "Hello")
        self.assertIn("http://example.com", parsed.urls)

    def test_parse_manual_email_empty_body_warns(self):
        parsed = parse_manual_email("a@b.com", "c@d.com", "Subj", "")
        self.assertTrue(len(parsed.parse_warnings) > 0)

    def test_parse_eml_bytes_empty_raises(self):
        with self.assertRaises(EmailParseError):
            parse_eml_bytes(b"")

    def test_parse_eml_bytes_simple(self):
        raw = (
            b"From: Test Sender <sender@example.com>\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: Test subject\r\n"
            b"Date: Fri, 19 Sep 2026 10:00:00 +0000\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Hello, please visit http://example.com/verify to continue.\r\n"
        )
        parsed = parse_eml_bytes(raw)
        self.assertEqual(parsed.sender_email, "sender@example.com")
        self.assertEqual(parsed.subject, "Test subject")
        self.assertTrue(any("example.com" in u for u in parsed.urls))

    def test_parse_eml_bytes_oversized_rejected(self):
        huge = b"From: a@b.com\r\nSubject: x\r\n\r\n" + b"a" * (11 * 1024 * 1024)
        with self.assertRaises(EmailParseError):
            parse_eml_bytes(huge)


if __name__ == "__main__":
    unittest.main()
