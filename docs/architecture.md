# Architecture

## High-level pipeline

```
Email (.eml upload OR pasted fields)
        │
        ▼
Email Analysis Agent            (utils/email_parser.py, agents/email_agent.py)
   - stdlib `email` package only, no exec of anything
   - extracts headers, sender, recipient, subject, body (text+HTML), URLs, attachments
        │
        ├──► ML/NLP Detection Agent        (agents/ml_agent.py)
        │       TF-IDF vectorizer + best trained classifier → class probabilities
        │
        ├──► Sender Analysis Agent          (agents/sender_agent.py → security/sender_analyzer.py)
        │       domain mismatch, display-name/domain brand impersonation,
        │       free-email-provider check, SPF/DKIM/DMARC (only if headers present)
        │
        ├──► URL Analysis Agent             (agents/url_agent.py → security/url_analyzer.py)
        │       HTTPS, IP-literal URLs, @ symbol, shorteners, subdomain count,
        │       suspicious TLD, login/credential/verification keywords,
        │       encoding, length, look-alike/typosquat domain heuristic
        │
        ├──► Attachment Threat Analyzer     (agents/attachment_agent.py → security/attachment_analyzer.py)
        │       filename/extension/MIME static checks only — never opens/executes
        │
        └──► Content/Suspicious Language    (agents/content_agent.py)
                urgency, threat, credential/financial/OTP requests, impersonation,
                account-suspension phrasing — with exact match spans for highlighting
        │
        ▼
Attack-Type Classification Agent   (agents/attack_classifier.py)
   rule-based scoring over phrase categories → Credential Harvesting / BEC / Financial /
   Tech Support / Lottery / Delivery / Other
        │
        ▼
Risk Scoring Agent   (agents/risk_agent.py)
   deterministic weighted sum of the 6 factors above → 0-100 score, severity band,
   verdict (Legitimate / Spam / Phishing) — see methodology.md for exact formula
        │
        ▼
Explanation Agent   (agents/explanation_agent.py)
   Gemini (gemini-1.5-flash) narrates the *already computed* verdict, with a strict
   system instruction to treat the email as untrusted data and never change the verdict.
   Falls back to a local template-based explanation if Gemini is not configured/unavailable.
        │
        ▼
Remediation Agent   (agents/remediation_agent.py)
   builds the "Possible Attack Chain" and "I Already Clicked" incident-response guidance
```

`agents/orchestrator.py` wires all of the above together and is the single entry point the
Streamlit UI calls (`Orchestrator.analyze(parsed_email)`).

## Why multiple agents instead of one LLM call?

1. **Explainability** — every rule and score is inspectable code, not a black box.
2. **Determinism** — the same email always produces the same score (important for a security
   tool and for grading/demoing this project).
3. **Resilience** — if Gemini is unavailable, every other agent still runs; only the
   plain-language narration degrades to a local template.
4. **Separation of concerns** — each agent is independently unit-testable (see `tests/`).

## Data flow storage

Every analysis is persisted to SQLite (`database/database.py`, schema in
`database/schema.sql`) so the Dashboard and History pages are backed by real data, not
session-only state.

## Directory map

See the top-level `README.md` for the full folder structure.
