"""
Orchestrator — coordinates all specialized agents into one pipeline:

    Email Parser -> [ML Agent, Sender Agent, URL Agent, Attachment Agent,
                      Content Agent] -> Attack Classifier -> Risk Engine
                      -> Explanation Agent (Gemini or local fallback)

The final verdict/score always comes from the deterministic Risk Scoring
Agent; Gemini (via the Explanation Agent) only narrates it.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

from agents.email_agent import EmailAgent
from agents.ml_agent import MLAgent
from agents.sender_agent import SenderAgent
from agents.url_agent import UrlAgent
from agents.attachment_agent import AttachmentAgent
from agents.content_agent import ContentAgent
from agents.attack_classifier import AttackClassifierAgent
from agents.risk_agent import RiskScoringAgent
from agents.explanation_agent import ExplanationAgent
from utils.text_cleaner import truncate

# ML agent + explanation agent are stateful (load a model / configure an API
# client) so they are created once and reused across analyses.
_ml_agent = MLAgent()
_explanation_agent = ExplanationAgent()


@dataclass
class AnalysisResult:
    parsed_email: object
    ml_result: object
    sender_finding: object
    url_summary: dict
    attachment_summary: dict
    content_finding: object
    attack_result: object
    risk_result: object
    explanation: dict
    attack_chain: list
    parse_warnings: list = field(default_factory=list)


class Orchestrator:
    def __init__(self):
        self.email_agent = EmailAgent()
        self.ml_agent = _ml_agent
        self.sender_agent = SenderAgent()
        self.url_agent = UrlAgent()
        self.attachment_agent = AttachmentAgent()
        self.content_agent = ContentAgent()
        self.attack_classifier = AttackClassifierAgent()
        self.risk_agent = RiskScoringAgent()
        self.explanation_agent = _explanation_agent

    def analyze(self, parsed_email, use_gemini: bool = True) -> AnalysisResult:
        combined_text = f"{parsed_email.subject}\n{parsed_email.combined_body}"

        ml_result = self.ml_agent.run(combined_text)
        sender_finding = self.sender_agent.run(parsed_email)
        url_summary = self.url_agent.run(parsed_email.urls)
        attachment_summary = self.attachment_agent.run(parsed_email.attachments)
        content_finding = self.content_agent.run(combined_text)

        attack_result = self.attack_classifier.run(
            combined_text, url_summary, content_finding, ml_result.phishing_probability
        )

        risk_result = self.risk_agent.run(
            ml_result, sender_finding, url_summary, content_finding, attachment_summary
        )

        attack_chain = []
        from agents.remediation_agent import RemediationAgent
        remediation = RemediationAgent()
        if risk_result.verdict == "Phishing":
            attack_chain = remediation.get_attack_chain(attack_result.attack_type)

        explanation_context = {
            "verdict": risk_result.verdict,
            "score": risk_result.total_score,
            "severity": risk_result.severity,
            "attack_type": attack_result.attack_type if risk_result.verdict == "Phishing" else "N/A",
            "breakdown": [asdict(b) for b in risk_result.breakdown],
            "explanations": risk_result.explanations,
            "subject": parsed_email.subject,
            "sender": parsed_email.sender_raw or parsed_email.sender_email,
            "body_snippet": truncate(parsed_email.combined_body, 600),
        }
        explanation = (
            self.explanation_agent.run(explanation_context)
            if use_gemini
            else {"text": self.explanation_agent.run(explanation_context)["text"], "source": "local_fallback"}
        )

        return AnalysisResult(
            parsed_email=parsed_email,
            ml_result=ml_result,
            sender_finding=sender_finding,
            url_summary=url_summary,
            attachment_summary=attachment_summary,
            content_finding=content_finding,
            attack_result=attack_result,
            risk_result=risk_result,
            explanation=explanation,
            attack_chain=attack_chain,
            parse_warnings=getattr(parsed_email, "parse_warnings", []) or [],
        )
