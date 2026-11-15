# Scoring Methodology

## Risk score formula (deterministic, 0-100)

The Risk Scoring Agent (`agents/risk_agent.py`) combines six weighted factors. Each factor is
computed independently by its own agent, then scaled into its point allocation:

| Factor                       | How it's computed                                                             | Max points |
|-------------------------------|--------------------------------------------------------------------------------|-----------:|
| ML/NLP Detection               | `phishing_probability` (from the trained classifier) × 25                     | 25 |
| Sender Analysis                 | `sender_risk_points / 100` × 20                                               | 20 |
| URL Analysis                    | `max(url_risk_points across all links) / 100` × 20                            | 20 |
| Content/Language Analysis       | `content_risk_points / 100` × 15                                              | 15 |
| Attachment Analysis             | `max(attachment_risk_points) / 100` × 10                                      | 10 |
| Impersonation Signals           | display-name spoof / sender-domain lookalike / URL-domain lookalike → up to 10 | 10 |
| **Total**                       |                                                                                  | **100** |

The final score is the sum of all six, clamped to `[0, 100]` and rounded to the nearest
integer. **No randomness is involved anywhere in this formula** — the same input always
produces the same score (see `tests/test_risk_engine.py::test_score_is_deterministic`).

## Severity bands

| Score range | Severity |
|-------------|----------|
| 0–25        | Low      |
| 26–50       | Medium   |
| 51–75       | High     |
| 76–100      | Critical |

## Verdict logic

The verdict (`Legitimate` / `Spam` / `Phishing`) is derived from the total score **and** the
ML model's own predicted class + confidence, so a confidently-classified phishing email is not
missed just because the rule-based factors (e.g. no risky links) happened to find little:

```
if total_score >= 60:
    verdict = Phishing
elif ml_predicted_label == "phishing" and ml_confidence >= 0.55:
    verdict = Phishing
elif total_score >= 20 or (ml_predicted_label == "spam" and ml_confidence >= 0.5):
    verdict = Spam
else:
    verdict = Legitimate

# A confident ML "legitimate" call can pull a low-signal email back to Legitimate.
if ml_predicted_label == "legitimate" and ml_confidence >= 0.6 and total_score < 40:
    verdict = Legitimate
```

## Attack-type classification

`agents/attack_classifier.py` scores each candidate attack type (Credential Harvesting,
BEC/CEO Fraud, Financial Scam, Tech Support Scam, Lottery/Prize Scam, Delivery Scam) by
counting matches against hand-curated phrase lists (`security/security_rules.py`), plus a
small boost from URL keywords (login/credential pages) and the ML phishing probability. The
highest-scoring type is reported with a confidence value; if no category scores above a
minimum threshold, the result is `Other / Unknown`. This is a transparent rule-based
classifier, not a separate trained model — every decision can be traced to the phrase(s) that
triggered it (`AttackTypeResult.signals`).

## ML/NLP Detection Agent

- **Features**: TF-IDF, unigrams + bigrams, up to 5,000 features (`ml/train_model.py`).
- **Models compared**: Logistic Regression, Multinomial Naive Bayes, Random Forest (200 trees),
  Linear SVM (calibrated for probability output). All four are actually trained and evaluated
  on a held-out 25% split; the one with the highest **F1-macro** is saved.
- **Metrics reported** (in `ml/models/metrics.json`, printed by `train_model.py`): accuracy,
  precision/recall/F1 (macro), confusion matrix, ROC-AUC (macro, one-vs-rest). These are
  **real, computed numbers** — nothing is hard-coded.
- **Dataset**: by default, this project trains on whatever is placed at `data/dataset.csv` if
  present and valid; otherwise it falls back to the bundled synthetic dataset. See
  `data/README.md` for details and current caveats about dataset size/diversity.

## Honesty notes (per project requirements)

- SPF/DKIM/DMARC results are only reported if the corresponding header was actually present in
  the `.eml`/pasted email; otherwise the UI explicitly says "not present in email".
- URL and attachment analysis are **static only** — no link is visited, no DNS is resolved, no
  attachment is opened, executed, or scanned by an antivirus engine. This is stated in the UI
  and in the PDF report.
- The "Possible Attack Chain" is explicitly labeled as a *potential* path inferred from
  detected indicators, not a confirmed real-world attack.
