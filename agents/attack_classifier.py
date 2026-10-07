"""
Attack-Type Classification Agent.

Uses a transparent, rule-based scoring approach over phrase categories and
URL/content signals (no black-box model — every decision is explainable).
Attack types: Credential Harvesting, BEC/CEO Fraud, Financial Scam,
Tech Support Scam, Lottery/Prize Scam, Delivery Scam, Other/Unknown.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from security.security_rules import (
    PRIZE_PHRASES, DELIVERY_PHRASES, TECH_SUPPORT_PHRASES, BEC_PHRASES,
    CREDENTIAL_REQUEST_PHRASES, FINANCIAL_REQUEST_PHRASES,
)

ATTACK_TYPES = [
    "Credential Harvesting", "BEC / CEO Fraud", "Financial Scam",
    "Tech Support Scam", "Lottery / Prize Scam", "Delivery Scam", "Other / Unknown",
]


@dataclass
class AttackTypeResult:
    attack_type: str
    confidence: float  # 0-1
    scores: dict = field(default_factory=dict)
    signals: list = field(default_factory=list)


class AttackClassifierAgent:
    name = "Attack-Type Classification Agent"

    def run(self, text: str, url_summary: dict, content_finding, ml_phishing_prob: float) -> AttackTypeResult:
        lower = (text or "").lower()
        scores = {t: 0.0 for t in ATTACK_TYPES}
        signals = []

        def add(attack_type, amount, reason):
            scores[attack_type] += amount
            signals.append(f"[{attack_type}] {reason}")

        cred_hits = sum(1 for p in CREDENTIAL_REQUEST_PHRASES if p in lower)
        login_url = any(f.has_login_keyword or f.has_credential_keyword for f in url_summary.get("findings", []))
        if cred_hits:
            add("Credential Harvesting", cred_hits * 15, f"{cred_hits} credential-request phrase(s) found.")
        if login_url:
            add("Credential Harvesting", 20, "A link references login/credential pages.")
        if content_finding and "OTP/Password Request" in content_finding.category_counts:
            add("Credential Harvesting", 15, "OTP/password request language detected.")

        bec_hits = sum(1 for p in BEC_PHRASES if p in lower)
        if bec_hits:
            add("BEC / CEO Fraud", bec_hits * 20, f"{bec_hits} business-email-compromise phrase(s) found (e.g. urgent wire/payment requests).")

        fin_hits = sum(1 for p in FINANCIAL_REQUEST_PHRASES if p in lower)
        if fin_hits:
            add("Financial Scam", fin_hits * 12, f"{fin_hits} financial-request phrase(s) found.")

        tech_hits = sum(1 for p in TECH_SUPPORT_PHRASES if p in lower)
        if tech_hits:
            add("Tech Support Scam", tech_hits * 20, f"{tech_hits} tech-support-scam phrase(s) found.")

        prize_hits = sum(1 for p in PRIZE_PHRASES if p in lower)
        if prize_hits:
            add("Lottery / Prize Scam", prize_hits * 20, f"{prize_hits} prize/lottery phrase(s) found.")

        delivery_hits = sum(1 for p in DELIVERY_PHRASES if p in lower)
        if delivery_hits:
            add("Delivery Scam", delivery_hits * 20, f"{delivery_hits} delivery-scam phrase(s) found.")

        # Small nudge from ML probability toward Credential Harvesting / Financial Scam,
        # since those are the most common phishing patterns in typical datasets.
        if ml_phishing_prob and ml_phishing_prob > 0.5:
            add("Credential Harvesting", ml_phishing_prob * 8, "ML model assigned a high phishing probability.")

        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]
        total = sum(scores.values()) or 1.0

        if best_score < 10:
            return AttackTypeResult(
                attack_type="Other / Unknown",
                confidence=0.3,
                scores=scores,
                signals=signals or ["No specific attack-type phrase patterns were matched."],
            )

        confidence = min(0.95, round(best_score / (total + 1e-6), 2) + 0.15)
        return AttackTypeResult(attack_type=best_type, confidence=confidence, scores=scores, signals=signals)
