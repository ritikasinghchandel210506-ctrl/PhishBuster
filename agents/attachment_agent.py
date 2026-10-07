"""Attachment Threat Analyzer agent — thin wrapper around
security.attachment_analyzer. Never opens or executes attachments."""
from __future__ import annotations

from security.attachment_analyzer import analyze_attachments


class AttachmentAgent:
    name = "Attachment Threat Analyzer"

    def run(self, attachments: list) -> dict:
        return analyze_attachments(attachments or [])
