"""URL Analysis Agent — thin wrapper around security.url_analyzer for the
orchestrator's agent interface."""
from __future__ import annotations

from security.url_analyzer import analyze_urls


class UrlAgent:
    name = "URL Analysis Agent"

    def run(self, urls: list) -> dict:
        return analyze_urls(urls or [])
