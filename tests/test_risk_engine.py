import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agents.orchestrator import Orchestrator
from agents.email_agent import EmailAgent


class TestRiskEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.email_agent = EmailAgent()
        cls.orchestrator = Orchestrator()

    def test_legitimate_email_low_score(self):
        parsed = self.email_agent.run_from_manual(
            "Sarah <sarah@company.com>", "team@company.com",
            "Meeting notes", "Hi team, attaching notes from today's meeting. Thanks, Sarah",
        )
        result = self.orchestrator.analyze(parsed, use_gemini=False)
        self.assertLessEqual(result.risk_result.total_score, 30)
        self.assertIn(result.risk_result.verdict, ("Legitimate", "Spam"))

    def test_phishing_email_high_score(self):
        parsed = self.email_agent.run_from_manual(
            "PayPal Support <support@paypal-alerts.tk>", "user@example.com",
            "Urgent: Verify your account now",
            "Your account will be suspended within 24 hours unless you verify your identity. "
            "Click here to confirm your password: http://paypal-secure-verify.tk/login",
        )
        result = self.orchestrator.analyze(parsed, use_gemini=False)
        self.assertEqual(result.risk_result.verdict, "Phishing")
        self.assertGreaterEqual(result.risk_result.total_score, 40)

    def test_score_is_deterministic(self):
        parsed1 = self.email_agent.run_from_manual("a@b.com", "c@d.com", "Subj", "Some body text with http://example.com")
        parsed2 = self.email_agent.run_from_manual("a@b.com", "c@d.com", "Subj", "Some body text with http://example.com")
        r1 = self.orchestrator.analyze(parsed1, use_gemini=False)
        r2 = self.orchestrator.analyze(parsed2, use_gemini=False)
        self.assertEqual(r1.risk_result.total_score, r2.risk_result.total_score)

    def test_severity_matches_score_bands(self):
        parsed = self.email_agent.run_from_manual("a@b.com", "c@d.com", "Subj", "hello")
        result = self.orchestrator.analyze(parsed, use_gemini=False)
        score = result.risk_result.total_score
        severity = result.risk_result.severity
        if score <= 25:
            self.assertEqual(severity, "Low")
        elif score <= 50:
            self.assertEqual(severity, "Medium")
        elif score <= 75:
            self.assertEqual(severity, "High")
        else:
            self.assertEqual(severity, "Critical")


if __name__ == "__main__":
    unittest.main()
