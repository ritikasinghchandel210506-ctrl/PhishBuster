"""
Lightweight, dependency-free text cleaning utilities for email content.

Deliberately avoids nltk/spaCy downloads so the project runs offline on a
fresh Windows machine with only the packages in requirements.txt.
"""
from __future__ import annotations

import re

# A small, hand-picked English stopword list (no external download needed).
STOPWORDS = {
    "a", "an", "the", "and", "or", "but", "if", "then", "so", "of", "to",
    "in", "on", "at", "for", "with", "as", "by", "is", "are", "was", "were",
    "be", "been", "being", "this", "that", "these", "those", "it", "its",
    "from", "you", "your", "yours", "we", "our", "i", "he", "she", "they",
    "them", "his", "her", "their", "will", "would", "can", "could", "should",
    "have", "has", "had", "do", "does", "did", "not", "no", "yes", "please",
    "dear", "regards", "sincerely", "thank", "thanks",
}

HTML_TAG_RE = re.compile(r"<[^>]+>")
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
WHITESPACE_RE = re.compile(r"\s+")
NON_ALNUM_RE = re.compile(r"[^a-zA-Z0-9\s]")


def strip_html(text: str) -> str:
    """Remove HTML tags, leaving visible text only."""
    if not text:
        return ""
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
    text = HTML_TAG_RE.sub(" ", text)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&")
    return WHITESPACE_RE.sub(" ", text).strip()


def extract_urls(text: str) -> list:
    """Extract raw URLs from plain or HTML text (also catches href= links)."""
    if not text:
        return []
    urls = set(URL_RE.findall(text))
    for match in re.findall(r'href=["\']([^"\']+)["\']', text, re.IGNORECASE):
        if match.lower().startswith("http") or match.lower().startswith("www"):
            urls.add(match)
    cleaned = []
    for u in urls:
        u = u.rstrip('.,;)\'"')
        cleaned.append(u)
    return sorted(set(cleaned))


def clean_for_ml(text: str) -> str:
    """Normalize text for TF-IDF: lowercase, strip HTML/URLs/punctuation, remove stopwords."""
    if not text:
        return ""
    text = strip_html(text)
    text = URL_RE.sub(" urltoken ", text)
    text = text.lower()
    text = NON_ALNUM_RE.sub(" ", text)
    tokens = [t for t in text.split() if t not in STOPWORDS and len(t) > 1]
    return " ".join(tokens)


def truncate(text: str, max_len: int = 400) -> str:
    if text is None:
        return ""
    text = text.strip()
    return text if len(text) <= max_len else text[: max_len - 3] + "..."
