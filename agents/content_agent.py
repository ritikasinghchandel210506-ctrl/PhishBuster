"""Content / Suspicious Language Agent.

Scans the email body for social-engineering language patterns and returns
categorized findings plus the exact phrases matched, so the UI can
highlight them in the original text.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from security.security_rules import (
    URGENCY_PHRASES, THREAT_PHRASES, CREDENTIAL_REQUEST_PHRASES,
    FINANCIAL_REQUEST_PHRASES, IMPERSONATION_PHRASES, OTP_PASSWORD_PHRASES,
    ACCOUNT_SUSPENSION_PHRASES,
)

CATEGORY_PHRASE_MAP = {
    "Urgency": URGENCY_PHRASES,
    "Threat": THREAT_PHRASES,
    "Credential Request": CREDENTIAL_REQUEST_PHRASES,
    "Financial Request": FINANCIAL_REQUEST_PHRASES,
    "Impersonation": IMPERSONATION_PHRASES,
    "OTP/Password Request": OTP_PASSWORD_PHRASES,
    "Account Suspension": ACCOUNT_SUSPENSION_PHRASES,
}


@dataclass
class ContentMatch:
    category: str
    phrase: str
    start: int
    end: int


@dataclass
class ContentFinding:
    matches: list = field(default_factory=list)
    category_counts: dict = field(default_factory=dict)
    risk_points: int = 0  # 0-100


CATEGORY_WEIGHT = {
    "Urgency": 8,
    "Threat": 12,
    "Credential Request": 18,
    "Financial Request": 15,
    "Impersonation": 12,
    "OTP/Password Request": 15,
    "Account Suspension": 12,
}


class ContentAgent:
    name = "Content/Suspicious Language Agent"

    def run(self, text: str) -> ContentFinding:
        finding = ContentFinding()
        if not text:
            return finding
        lower = text.lower()
        matches = []
        counts = {}
        points = 0

        for category, phrases in CATEGORY_PHRASE_MAP.items():
            hit_in_category = False
            for phrase in phrases:
                idx = lower.find(phrase)
                if idx != -1:
                    matches.append(ContentMatch(category=category, phrase=phrase, start=idx, end=idx + len(phrase)))
                    counts[category] = counts.get(category, 0) + 1
                    hit_in_category = True
            if hit_in_category:
                points += CATEGORY_WEIGHT[category]

        finding.matches = sorted(matches, key=lambda m: m.start)
        finding.category_counts = counts
        finding.risk_points = min(100, points)
        return finding
