# Security Considerations

This is a defensive, academic security tool. It follows these practices:

- **No attachment is ever opened, executed, or run** — only filename, extension, declared MIME
  type, and byte size are inspected (`security/attachment_analyzer.py`).
- **No URL is ever visited, fetched, or resolved** — all URL analysis is static string
  parsing (`security/url_analyzer.py`); no `requests`/`urllib` network calls are made against
  any URL found in an email.
- **Untrusted input handling**: all displayed email content (subject/body/sender) is escaped
  via `utils/helpers.escape_html` before being rendered as HTML in Streamlit, so an email
  cannot inject markup/script into the app's own UI.
- **Upload limits**: `.eml` uploads are capped at 10 MB (`utils/email_parser.MAX_EML_SIZE_BYTES`)
  and validated before parsing; malformed files raise a caught, user-friendly error instead of
  crashing the app.
- **Prompt-injection resistance for the Explanation Agent**: the Gemini system instruction
  explicitly tells the model to treat the email content as untrusted data, to never follow
  instructions embedded in it, to never reveal secrets, and to never change the
  deterministic verdict/score — it may only narrate the analysis already computed
  (`agents/explanation_agent.py`).
- **Secrets management**: the Gemini API key is read only from the `GEMINI_API_KEY`
  environment variable via `python-dotenv`; it is never hard-coded, logged, or written into
  generated PDF reports. `.env` is git-ignored; only `.env.example` (with a placeholder) is
  committed.
- **SQL injection**: every database query in `database/database.py` uses parameterized
  queries (`?` placeholders) — no string-formatted SQL.
- **Graceful degradation**: the app is designed to keep working when a dependency is missing —
  no trained ML model → the ML factor contributes 0 and the UI shows a setup message; no
  Gemini key → a local template explanation is used instead; a malformed email → a caught,
  readable error instead of a crash.
- **No offensive guidance**: the Incident-Response ("I Already Clicked") agent only ever gives
  defensive remediation steps (change passwords, contact your bank, notify IT) — never
  retaliatory or offensive actions.

## Known limitations (intentionally disclosed, not hidden)

- This tool does not perform sandboxed malware detonation or real antivirus scanning.
- It does not perform live DNS/SPF/DKIM/DMARC verification — only what is present in the
  email's own headers is evaluated.
- Rule-based phrase lists and the small bundled/user-supplied training datasets mean the tool
  can be evaded by sufficiently novel phishing text, and can produce false positives/negatives —
  like any phishing detector. It is a decision-support tool, not a guarantee.
