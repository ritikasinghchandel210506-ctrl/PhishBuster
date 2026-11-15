"""
Static URL analysis (no network requests are made — nothing is visited,
resolved, or executed). Every check here works purely on the URL string.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from security.security_rules import (
    SUSPICIOUS_TLDS, KNOWN_TWO_PART_SUFFIXES, URL_SHORTENERS,
    LOGIN_KEYWORDS, CREDENTIAL_KEYWORDS, VERIFICATION_KEYWORDS,
)

IP_URL_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _registrable_domain(host: str) -> str:
    """Best-effort domain extraction without external dependencies."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in KNOWN_TWO_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


@dataclass
class UrlFinding:
    url: str
    domain: str = ""
    is_https: bool = False
    is_ip_address: bool = False
    has_at_symbol: bool = False
    is_shortened: bool = False
    subdomain_count: int = 0
    suspicious_tld: bool = False
    has_login_keyword: bool = False
    has_credential_keyword: bool = False
    has_verification_keyword: bool = False
    excessive_encoding: bool = False
    unusually_long: bool = False
    lookalike_suspected: bool = False
    reasons: list = field(default_factory=list)
    risk_points: int = 0  # 0-100 per-url risk contribution


KNOWN_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook",
    "instagram", "bankofamerica", "chase", "wellsfargo", "dhl", "fedex", "ups",
    "linkedin", "irs", "hdfcbank", "icicibank", "sbi", "outlook", "office365",
]


def _lookalike_check(domain: str) -> bool:
    """Very lightweight typosquat heuristic: brand name present but domain
    is not actually that brand's real registrable domain."""
    base = domain.split(".")[0] if domain else ""
    for brand in KNOWN_BRANDS:
        if brand in domain and not domain.startswith(brand + "."):
            return True
        if brand in base and base != brand:
            return True
    return False


def analyze_url(url: str) -> UrlFinding:
    finding = UrlFinding(url=url)
    reasons = []

    normalized = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(normalized)
    except Exception:
        finding.reasons = ["URL could not be parsed; treated as suspicious by default."]
        finding.risk_points = 40
        return finding

    host = parsed.hostname or ""
    finding.domain = _registrable_domain(host) if host else ""
    finding.is_https = parsed.scheme == "https"
    finding.is_ip_address = bool(IP_URL_RE.match(host))
    finding.has_at_symbol = "@" in url
    finding.is_shortened = finding.domain in URL_SHORTENERS
    finding.subdomain_count = max(0, host.count(".") - 1) if host else 0
    tld = host.split(".")[-1] if "." in host else ""
    finding.suspicious_tld = tld in SUSPICIOUS_TLDS
    lower_url = url.lower()
    finding.has_login_keyword = any(k in lower_url for k in LOGIN_KEYWORDS)
    finding.has_credential_keyword = any(k in lower_url for k in CREDENTIAL_KEYWORDS)
    finding.has_verification_keyword = any(k in lower_url for k in VERIFICATION_KEYWORDS)
    finding.excessive_encoding = url.count("%") >= 3
    finding.unusually_long = len(url) > 90
    finding.lookalike_suspected = _lookalike_check(finding.domain)

    points = 0
    if not finding.is_https:
        points += 12
        reasons.append("Link does not use HTTPS.")
    if finding.is_ip_address:
        points += 25
        reasons.append("Link points directly to an IP address instead of a domain name.")
    if finding.has_at_symbol:
        points += 20
        reasons.append("Link contains an '@' symbol, which can hide the real destination.")
    if finding.is_shortened:
        points += 15
        reasons.append(f"Link uses a URL shortener ({finding.domain}); real destination is hidden.")
    if finding.subdomain_count >= 3:
        points += 10
        reasons.append("Link has an unusually high number of subdomains.")
    if finding.suspicious_tld:
        points += 12
        reasons.append(f"Link uses a top-level domain ('.{tld}') often associated with abuse.")
    if finding.has_login_keyword:
        points += 8
        reasons.append("Link text/path references login or account pages.")
    if finding.has_credential_keyword:
        points += 10
        reasons.append("Link references passwords/OTP/credentials.")
    if finding.has_verification_keyword:
        points += 6
        reasons.append("Link references identity/account verification.")
    if finding.excessive_encoding:
        points += 10
        reasons.append("Link contains excessive percent-encoding, which can obscure its true target.")
    if finding.unusually_long:
        points += 8
        reasons.append("Link is unusually long, a pattern sometimes used to hide the real domain.")
    if finding.lookalike_suspected:
        points += 20
        reasons.append(f"Link domain ('{finding.domain}') resembles a well-known brand but does not match it exactly (possible look-alike domain).")

    finding.risk_points = min(100, points)
    finding.reasons = reasons
    return finding


def analyze_urls(urls: list) -> dict:
    """Analyze a list of URLs and return a summary + per-url findings."""
    findings = [analyze_url(u) for u in urls]
    if not findings:
        return {
            "count": 0,
            "findings": [],
            "max_risk": 0,
            "avg_risk": 0,
            "flagged_count": 0,
            "note": "No URLs were found in this email.",
        }
    max_risk = max(f.risk_points for f in findings)
    avg_risk = sum(f.risk_points for f in findings) / len(findings)
    flagged = sum(1 for f in findings if f.risk_points >= 30)
    return {
        "count": len(findings),
        "findings": findings,
        "max_risk": max_risk,
        "avg_risk": round(avg_risk, 1),
        "flagged_count": flagged,
        "note": "Static analysis only — no links were visited or resolved.",
    }
