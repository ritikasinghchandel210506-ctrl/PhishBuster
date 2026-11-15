"""Small shared helpers: html escaping, severity mapping, timestamps."""
from __future__ import annotations

import html
import re
from datetime import datetime


def severity_from_score(score: float) -> str:
    """Map a 0-100 risk score to a severity band."""
    score = max(0, min(100, score))
    if score <= 25:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 75:
        return "High"
    return "Critical"


SEVERITY_COLORS = {
    "Low": "#2ecc71",
    "Medium": "#f1c40f",
    "High": "#e67e22",
    "Critical": "#e74c3c",
}

VERDICT_COLORS = {
    "Legitimate": "#2ecc71",
    "Spam": "#f39c12",
    "Phishing": "#e74c3c",
}


def escape_html(text: str) -> str:
    """Escape untrusted text before rendering it in the Streamlit UI as HTML."""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def format_timestamp(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%d %b %Y, %I:%M %p")
    except Exception:
        return ts or "Unknown"


def clamp(value: float, lo: float = 0, hi: float = 100) -> float:
    return max(lo, min(hi, value))


def safe_filename(name: str) -> str:
    """Strip characters that are unsafe in a filename (used for uploaded files)."""
    name = re.sub(r"[^A-Za-z0-9_.\-]", "_", name or "upload")
    return name[:150]
