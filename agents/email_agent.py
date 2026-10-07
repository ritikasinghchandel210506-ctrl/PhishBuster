"""Email Analysis Agent — turns raw input (.eml bytes or manual fields) into
a structured ParsedEmail the rest of the pipeline can consume."""
from __future__ import annotations

from utils.email_parser import parse_eml_bytes, parse_manual_email, EmailParseError, ParsedEmail


class EmailAgent:
    name = "Email Analysis Agent"

    def run_from_eml(self, raw_bytes: bytes) -> ParsedEmail:
        return parse_eml_bytes(raw_bytes)

    def run_from_manual(self, sender: str, recipient: str, subject: str, body: str) -> ParsedEmail:
        return parse_manual_email(sender, recipient, subject, body)
