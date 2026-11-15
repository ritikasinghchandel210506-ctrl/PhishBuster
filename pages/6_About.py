"""About page — project overview, architecture, methodology, limitations."""
from __future__ import annotations

import streamlit as st

st.set_page_config(page_title="About | AI Phishing Detector", page_icon="ℹ️", layout="wide")
st.title("About This Project")

st.markdown("""

Traditional phishing detection often relies on a single indicator (a blocklist, a single ML
model, or a single LLM prompt) and rarely explains *why* an email was flagged. This makes it
hard for a non-technical user to trust — or learn from — the result.

Rather than asking a single LLM "is this phishing?", the system routes an email through
**specialized agents** that each inspect one dimension of risk, then combines their outputs
with a transparent, reproducible formula. Generative AI is used only to *explain* the result
in plain language — it cannot override the computed verdict. This makes every decision
auditable, which matters a great deal in a security context.

## Architecture
```
Email (.eml or pasted)
      │
      ▼
Email Analysis Agent  (parses headers, body, URLs, attachments)
      │
      ├──► ML/NLP Detection Agent        (TF-IDF + trained classifier)
      ├──► Sender Analysis Agent          (domain mismatch, SPF/DKIM/DMARC if present, impersonation)
      ├──► URL Analysis Agent             (HTTPS, IP URLs, shorteners, look-alike domains, ...)
      ├──► Attachment Threat Analyzer     (extension/MIME static checks only)
      └──► Content/Suspicious Language    (urgency, threats, credential/financial requests, ...)
      │
      ▼
Attack-Type Classification Agent   (rule-based: Credential Harvesting, BEC, ...)
      │
      ▼
Risk Scoring Agent   (deterministic 0-100 score, documented weights — see docs/methodology.md)
      │
      ▼
Explanation Agent   (Gemini, or a local template fallback if unavailable)
      │
      ▼
Remediation Agent   (attack chain + "I Already Clicked" guidance)
```
""")
