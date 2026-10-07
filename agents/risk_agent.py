"""
Risk Scoring Agent — combines every other agent's output into a single,
transparent, deterministic 0-100 score using a fixed, documented formula.
The same input always produces the same score (no randomness).

Documented weighting (matches docs/methodology.md):

    ML Detection (phishing probability)........ 25 points
    Sender Risk.................................. 20 points
    URL Risk...................................... 20 points
    Content / Language Risk...................... 15 points
    Attachment Risk............................... 10 points
    Impersonation signals......................... 10 points
    ----------------------------------------------------
    TOTAL......................................... 100 points
"""
from __future__ import annotations

from dataclasses import dataclass, field

WEIGHTS = {
    "ml_detection": 25,
    "sender_risk": 20,
    "url_risk": 20,
    "content_risk": 15,
    "attachment_risk": 10,
    "impersonation": 10,
}


@dataclass
class RiskBreakdown:
    factor: str
    label: str
    points: float
    max_points: float


@dataclass
class RiskResult:
    total_score: int
    severity: str
    verdict: str
    breakdown: list = field(default_factory=list)
    explanations: list = field(default_factory=list)


def _severity(score: int) -> str:
    if score <= 25:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 75:
        return "High"
    return "Critical"


class RiskScoringAgent:
    name = "Risk Scoring Agent"

    def run(self, ml_result, sender_finding, url_summary, content_finding, attachment_summary) -> RiskResult:
        explanations = []
        breakdown = []

        # 1) ML detection contribution
        ml_prob = ml_result.phishing_probability if ml_result.available else 0.0
        ml_points = round(ml_prob * WEIGHTS["ml_detection"], 1)
        breakdown.append(RiskBreakdown("ml_detection", "ML/NLP Detection", ml_points, WEIGHTS["ml_detection"]))
        if ml_result.available and ml_prob > 0.5:
            explanations.append(f"The ML model estimated a {ml_prob*100:.0f}% probability that this email is phishing.")
        elif not ml_result.available:
            explanations.append("ML model was unavailable; this factor contributed 0 points (train the model with ml/train_model.py).")

        # 2) Sender risk
        sender_points = round((sender_finding.risk_points / 100) * WEIGHTS["sender_risk"], 1)
        breakdown.append(RiskBreakdown("sender_risk", "Sender Analysis", sender_points, WEIGHTS["sender_risk"]))
        explanations.extend(sender_finding.reasons[:3])

        # 3) URL risk
        url_max = url_summary.get("max_risk", 0)
        url_points = round((url_max / 100) * WEIGHTS["url_risk"], 1)
        breakdown.append(RiskBreakdown("url_risk", "URL Analysis", url_points, WEIGHTS["url_risk"]))
        if url_summary.get("count", 0) > 0:
            top = max(url_summary["findings"], key=lambda f: f.risk_points)
            explanations.extend(top.reasons[:2])

        # 4) Content / language risk
        content_points = round((content_finding.risk_points / 100) * WEIGHTS["content_risk"], 1)
        breakdown.append(RiskBreakdown("content_risk", "Content/Language Analysis", content_points, WEIGHTS["content_risk"]))
        if content_finding.category_counts:
            cats = ", ".join(content_finding.category_counts.keys())
            explanations.append(f"Suspicious language categories detected: {cats}.")

        # 5) Attachment risk
        att_max = attachment_summary.get("max_risk", 0)
        att_points = round((att_max / 100) * WEIGHTS["attachment_risk"], 1)
        breakdown.append(RiskBreakdown("attachment_risk", "Attachment Analysis", att_points, WEIGHTS["attachment_risk"]))
        if attachment_summary.get("count", 0) > 0:
            top_att = max(attachment_summary["findings"], key=lambda f: f.risk_points)
            if top_att.risk_points > 0:
                explanations.extend(top_att.reasons[:2])

        # 6) Impersonation signals (sender display-name spoof OR look-alike URL domain)
        impersonation_signal = 0
        if sender_finding.display_name_impersonation:
            impersonation_signal += 50
        if getattr(sender_finding, "domain_lookalike", False):
            impersonation_signal += 50
        url_lookalike = any(f.lookalike_suspected for f in url_summary.get("findings", []))
        if url_lookalike:
            impersonation_signal += 50
        impersonation_points = round(min(100, impersonation_signal) / 100 * WEIGHTS["impersonation"], 1)
        breakdown.append(RiskBreakdown("impersonation", "Impersonation Signals", impersonation_points, WEIGHTS["impersonation"]))
        if sender_finding.display_name_impersonation:
            explanations.append("Sender display name appears to impersonate a known brand.")
        if getattr(sender_finding, "domain_lookalike", False):
            explanations.append("Sender's domain resembles a well-known brand without being an exact match.")
        if url_lookalike:
            explanations.append("One or more links use a domain that resembles a well-known brand.")

        total = sum(b.points for b in breakdown)
        total = int(round(max(0, min(100, total))))
        severity = _severity(total)

        # Verdict combines the deterministic risk score with the ML model's
        # own class prediction: a very high total score is phishing on its
        # own merits, but a confident ML "phishing"/"spam" call also counts
        # even when the rule-based factors (URL/sender/attachment) found
        # little to flag (e.g. a phishing email with no links, just text).
        ml_label = ml_result.predicted_label if ml_result.available else None
        ml_confidence = max(ml_result.probabilities.values()) if (ml_result.available and ml_result.probabilities) else 0.0

        if total >= 60:
            verdict = "Phishing"
        elif ml_label == "phishing" and ml_confidence >= 0.55:
            verdict = "Phishing"
        elif total >= 20 or (ml_label == "spam" and ml_confidence >= 0.5):
            verdict = "Spam"
        else:
            verdict = "Legitimate"

        # A very confident ML "legitimate" call pulls a low-signal email back
        # to Legitimate even if a minor rule nudged the score up slightly.
        if ml_label == "legitimate" and ml_confidence >= 0.6 and total < 40:
            verdict = "Legitimate"

        dedup_explanations = list(dict.fromkeys(explanations))[:8]
        if not dedup_explanations:
            dedup_explanations = ["No significant risk indicators were found across sender, URL, content, or attachment analysis."]

        return RiskResult(
            total_score=total, severity=severity, verdict=verdict,
            breakdown=breakdown, explanations=dedup_explanations,
        )
