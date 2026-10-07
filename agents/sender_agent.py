"""Sender Analysis Agent — thin wrapper around security.sender_analyzer."""
from __future__ import annotations

from security.sender_analyzer import analyze_sender


class SenderAgent:
    name = "Sender Analysis Agent"

    def run(self, parsed_email):
        return analyze_sender(parsed_email)
