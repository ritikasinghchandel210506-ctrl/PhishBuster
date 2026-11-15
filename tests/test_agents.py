import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agents.content_agent import ContentAgent
from agents.attack_classifier import AttackClassifierAgent
from agents.sender_agent import SenderAgent
from agents.attachment_agent import AttachmentAgent
from agents.email_agent import EmailAgent
from utils.email_parser import ParsedAttachment


class TestContentAgent(unittest.TestCase):
    def test_detects_urgency_and_credential_request(self):
        agent = ContentAgent()
        finding = agent.run("This is urgent, please verify your account and enter your password now.")
        self.assertIn("Urgency", finding.category_counts)
        self.assertGreater(finding.risk_points, 0)

    def test_empty_text_no_matches(self):
        agent = ContentAgent()
        finding = agent.run("")
        self.assertEqual(finding.matches, [])
        self.assertEqual(finding.risk_points, 0)


class TestAttackClassifier(unittest.TestCase):
    def test_credential_harvesting_detected(self):
        agent = AttackClassifierAgent()
        from agents.content_agent import ContentAgent
        content = ContentAgent().run("Please verify your account and enter your password to continue.")
        result = agent.run(
            "Please verify your account and enter your password to continue.",
            {"findings": []}, content, ml_phishing_prob=0.8,
        )
        self.assertEqual(result.attack_type, "Credential Harvesting")

    def test_no_signals_returns_unknown(self):
        agent = AttackClassifierAgent()
        from agents.content_agent import ContentAgent
        content = ContentAgent().run("Hi, let's meet for coffee tomorrow.")
        result = agent.run("Hi, let's meet for coffee tomorrow.", {"findings": []}, content, ml_phishing_prob=0.0)
        self.assertEqual(result.attack_type, "Other / Unknown")


class TestSenderAgent(unittest.TestCase):
    def test_domain_mismatch_flagged(self):
        agent = SenderAgent()
        email_agent = EmailAgent()
        parsed = email_agent.run_from_manual(
            "Bank <alerts@mybank-secure.com>", "user@example.com", "Subj", "body"
        )
        parsed.reply_to = "replies@totally-different.com"
        finding = agent.run(parsed)
        self.assertTrue(finding.domain_mismatch)


class TestAttachmentAgent(unittest.TestCase):
    def test_dangerous_extension_flagged(self):
        agent = AttachmentAgent()
        summary = agent.run([ParsedAttachment(filename="invoice.exe", content_type="application/octet-stream", size_bytes=1024)])
        self.assertEqual(summary["count"], 1)
        self.assertTrue(summary["findings"][0].is_dangerous_extension)

    def test_no_attachments(self):
        agent = AttachmentAgent()
        summary = agent.run([])
        self.assertEqual(summary["count"], 0)


if __name__ == "__main__":
    unittest.main()
