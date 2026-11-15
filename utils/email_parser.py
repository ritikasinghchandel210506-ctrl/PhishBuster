"""
Safe .eml parsing using only Python's standard library `email` package.

No attachment is ever executed or opened; only metadata (filename, size,
MIME type) is extracted for static analysis by the attachment agent.
"""
from __future__ import annotations

import email
import email.utils
from email import policy
from dataclasses import dataclass, field
from typing import Optional

from utils.text_cleaner import extract_urls, strip_html

MAX_EML_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB safety cap


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str
    size_bytes: int


@dataclass
class ParsedEmail:
    sender_raw: str = ""
    sender_email: str = ""
    sender_display_name: str = ""
    reply_to: str = ""
    recipient: str = ""
    subject: str = ""
    date: str = ""
    body_text: str = ""
    body_html: str = ""
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    auth_headers_present: bool = False
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    parse_warnings: list = field(default_factory=list)

    @property
    def combined_body(self) -> str:
        html_text = strip_html(self.body_html) if self.body_html else ""
        parts = [p for p in (self.body_text, html_text) if p]
        return "\n".join(parts)


class EmailParseError(Exception):
    pass


def _get_header(msg, name: str) -> str:
    try:
        val = msg.get(name, "")
        return str(val) if val else ""
    except Exception:
        return ""


def _extract_auth_results(msg) -> tuple[Optional[str], Optional[str], Optional[str], bool]:
    """
    Look for SPF/DKIM/DMARC verdicts inside Authentication-Results / Received-SPF
    headers, if present. Returns (spf, dkim, dmarc, any_header_found).
    We NEVER claim pass/fail if the header itself is absent.
    """
    auth_header = _get_header(msg, "Authentication-Results")
    received_spf = _get_header(msg, "Received-SPF")
    found = bool(auth_header or received_spf)

    def _find(pattern: str, text: str) -> Optional[str]:
        import re
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).lower() if m else None

    spf = None
    dkim = None
    dmarc = None
    if auth_header:
        spf = _find(r"spf=([a-z]+)", auth_header) or spf
        dkim = _find(r"dkim=([a-z]+)", auth_header)
        dmarc = _find(r"dmarc=([a-z]+)", auth_header)
    if received_spf and not spf:
        spf = _find(r"^([a-z]+)", received_spf.strip())

    return spf, dkim, dmarc, found


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into a ParsedEmail. Raises EmailParseError on
    unrecoverable failures; recoverable issues are recorded as warnings."""
    if not raw_bytes:
        raise EmailParseError("The uploaded file is empty.")
    if len(raw_bytes) > MAX_EML_SIZE_BYTES:
        raise EmailParseError(
            f"File is too large ({len(raw_bytes)/1_000_000:.1f} MB). "
            f"Maximum allowed size is {MAX_EML_SIZE_BYTES/1_000_000:.0f} MB."
        )

    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as exc:
        raise EmailParseError(f"Could not parse this file as a valid email: {exc}")

    parsed = ParsedEmail()
    warnings = []

    from_header = _get_header(msg, "From")
    parsed.sender_raw = from_header
    try:
        name, addr = email.utils.parseaddr(from_header)
        parsed.sender_display_name = name or ""
        parsed.sender_email = addr or ""
    except Exception:
        warnings.append("Could not fully parse the From header.")

    parsed.reply_to = _get_header(msg, "Reply-To")
    parsed.recipient = _get_header(msg, "To")
    parsed.subject = _get_header(msg, "Subject") or "(no subject)"
    parsed.date = _get_header(msg, "Date")

    for key in ("From", "To", "Subject", "Date", "Return-Path", "Message-ID",
                "Reply-To", "Received", "X-Mailer", "Content-Type"):
        val = _get_header(msg, key)
        if val:
            parsed.headers[key] = val

    spf, dkim, dmarc, found = _extract_auth_results(msg)
    parsed.spf, parsed.dkim, parsed.dmarc, parsed.auth_headers_present = spf, dkim, dmarc, found

    body_text_parts = []
    body_html_parts = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get_content_disposition() or "")
                content_type = part.get_content_type()

                if content_disposition == "attachment" or (
                    part.get_filename() and content_disposition != "inline"
                ):
                    filename = part.get_filename() or "unnamed_attachment"
                    try:
                        payload = part.get_payload(decode=True) or b""
                        size = len(payload)
                    except Exception:
                        size = 0
                        warnings.append(f"Could not read attachment '{filename}' safely.")
                    parsed.attachments.append(
                        ParsedAttachment(filename=filename, content_type=content_type, size_bytes=size)
                    )
                    continue

                if content_type == "text/plain" and content_disposition != "attachment":
                    try:
                        body_text_parts.append(part.get_content())
                    except Exception:
                        warnings.append("A text part could not be decoded.")
                elif content_type == "text/html" and content_disposition != "attachment":
                    try:
                        body_html_parts.append(part.get_content())
                    except Exception:
                        warnings.append("An HTML part could not be decoded.")
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
            except Exception:
                content = ""
                warnings.append("The email body could not be decoded.")
            if content_type == "text/html":
                body_html_parts.append(content)
            else:
                body_text_parts.append(content)
    except Exception as exc:
        warnings.append(f"Partial parse failure while walking MIME parts: {exc}")

    parsed.body_text = "\n".join(body_text_parts).strip()
    parsed.body_html = "\n".join(body_html_parts).strip()

    urls = set(extract_urls(parsed.body_text)) | set(extract_urls(parsed.body_html))
    parsed.urls = sorted(urls)
    parsed.parse_warnings = warnings

    if not parsed.body_text and not parsed.body_html:
        warnings.append("No readable email body was found.")

    return parsed


def parse_manual_email(sender: str, recipient: str, subject: str, body: str) -> ParsedEmail:
    """Build a ParsedEmail from manually pasted fields (no .eml file)."""
    parsed = ParsedEmail()
    name, addr = email.utils.parseaddr(sender or "")
    parsed.sender_raw = sender or ""
    parsed.sender_display_name = name or ""
    parsed.sender_email = addr or (sender or "").strip()
    parsed.recipient = recipient or ""
    parsed.subject = subject.strip() if subject else "(no subject)"
    parsed.body_text = body or ""
    parsed.urls = extract_urls(body or "")
    parsed.auth_headers_present = False
    if not (body or "").strip():
        parsed.parse_warnings.append("No email body was provided.")
    return parsed
