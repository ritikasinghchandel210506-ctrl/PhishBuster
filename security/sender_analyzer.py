"""Static sender / header analysis (no DNS lookups, no network access)."""
from __future__ import annotations

from dataclasses import dataclass, field

from security.security_rules import FREE_EMAIL_PROVIDERS, KNOWN_TWO_PART_SUFFIXES
from security.url_analyzer import KNOWN_BRANDS, _lookalike_check


@dataclass
class SenderFinding:
    sender_domain: str = ""
    reply_to_domain: str = ""
    domain_mismatch: bool = False
    display_name_impersonation: bool = False
    domain_lookalike: bool = False
    free_email_provider: bool = False
    suspicious_characters: bool = False
    spf_status: str = "Not present in email"
    dkim_status: str = "Not present in email"
    dmarc_status: str = "Not present in email"
    auth_headers_present: bool = False
    reasons: list = field(default_factory=list)
    risk_points: int = 0  # 0-100


def _domain_of(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.split("@")[-1].lower().strip()


def _base_label(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in KNOWN_TWO_PART_SUFFIXES:
        return labels[-3]
    return labels[0] if labels else domain


def analyze_sender(parsed_email) -> SenderFinding:
    finding = SenderFinding()
    reasons = []

    sender_domain = _domain_of(parsed_email.sender_email)
    reply_domain = _domain_of(parsed_email.reply_to) if parsed_email.reply_to else ""
    finding.sender_domain = sender_domain
    finding.reply_to_domain = reply_domain

    points = 0

    if reply_domain and sender_domain and reply_domain != sender_domain:
        finding.domain_mismatch = True
        points += 20
        reasons.append(
            f"Reply-To domain ('{reply_domain}') differs from the sending domain "
            f"('{sender_domain}') — replies would go somewhere else."
        )

    display_name = (parsed_email.sender_display_name or "").lower()
    for brand in KNOWN_BRANDS:
        if brand in display_name and sender_domain and brand not in sender_domain:
            finding.display_name_impersonation = True
            points += 22
            reasons.append(
                f"Display name mentions '{brand}' but the sending address domain "
                f"('{sender_domain}') does not belong to {brand}."
            )
            break

    if sender_domain and _lookalike_check(sender_domain):
        finding.domain_lookalike = True
        points += 25
        reasons.append(
            f"Sending domain ('{sender_domain}') resembles a well-known brand but does not "
            "exactly match that brand's real domain (possible look-alike/typosquatted domain)."
        )

    if sender_domain in FREE_EMAIL_PROVIDERS:
        finding.free_email_provider = True
        points += 8
        reasons.append(
            f"Sender uses a free/public email provider ({sender_domain}), which is "
            "uncommon for official organizational communication."
        )

    raw = parsed_email.sender_raw or ""
    suspicious_chars = any(ch in raw for ch in ["\u200b", "\u202e", "\ufeff"]) or bool(
        set(sender_domain) & set("0123456789")
    ) and any(b in sender_domain for b in KNOWN_BRANDS if b not in sender_domain)
    # Simpler, explicit check: mixed script / punycode marker
    if "xn--" in sender_domain:
        finding.suspicious_characters = True
        points += 15
        reasons.append("Sending domain uses punycode (xn--), sometimes used to spoof look-alike domains.")

    spf, dkim, dmarc = parsed_email.spf, parsed_email.dkim, parsed_email.dmarc
    finding.auth_headers_present = parsed_email.auth_headers_present

    if spf is not None:
        finding.spf_status = spf
        if spf not in ("pass",):
            points += 10
            reasons.append(f"SPF authentication result reported as '{spf}'.")
    if dkim is not None:
        finding.dkim_status = dkim
        if dkim not in ("pass",):
            points += 8
            reasons.append(f"DKIM authentication result reported as '{dkim}'.")
    if dmarc is not None:
        finding.dmarc_status = dmarc
        if dmarc not in ("pass",):
            points += 10
            reasons.append(f"DMARC authentication result reported as '{dmarc}'.")

    if not finding.auth_headers_present:
        reasons.append(
            "No Authentication-Results/Received-SPF headers were present in this email "
            "(common for pasted/manual input) — SPF/DKIM/DMARC could not be evaluated."
        )

    finding.risk_points = min(100, points)
    finding.reasons = reasons
    return finding
