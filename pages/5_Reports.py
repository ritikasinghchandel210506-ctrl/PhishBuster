"""Reports page — regenerate a PDF report for any past analysis in history."""
from __future__ import annotations

import json
import streamlit as st

from database.database import get_history
from reports.pdf_report import build_pdf_report
from utils.helpers import format_timestamp

st.set_page_config(page_title="Reports | AI Phishing Detector", page_icon="🧾", layout="wide")
st.title("Security Reports")
st.caption("Generate a downloadable PDF for any past analysis.")

history = get_history(limit=300)
if not history:
    st.info("No analyses yet.")
    st.page_link("pages/1_Analyze_Email.py", label="Analyze an email", icon="🔍")
    st.stop()

options = {f"#{h['id']} — {h['subject'] or '(no subject)'} — {h['verdict']} ({format_timestamp(h['timestamp'])})": h for h in history}
choice = st.selectbox("Choose an analysis", list(options.keys()))
row = options[choice]

try:
    indicators = json.loads(row["suspicious_indicators"] or "[]")
except json.JSONDecodeError:
    indicators = []

breakdown = [
    {"label": "ML/NLP Detection", "points": row["ml_probability"] or 0, "max_points": 25},
    {"label": "Sender Analysis", "points": row["sender_risk"] or 0, "max_points": 20},
    {"label": "URL Analysis", "points": row["url_risk"] or 0, "max_points": 20},
    {"label": "Content/Language Analysis", "points": row["content_risk"] or 0, "max_points": 15},
    {"label": "Attachment Analysis", "points": row["attachment_risk"] or 0, "max_points": 10},
    {"label": "Impersonation Signals", "points": row["impersonation_risk"] or 0, "max_points": 10},
]

recommended_actions = (
    ["Do not click links or open attachments from this email if it is not legitimate.",
     "Verify the sender through a separate, trusted channel before acting on any request.",
     "Report this email to your IT/security team if received on a work account."]
    if row["verdict"] != "Legitimate"
    else ["No action required — this email did not trigger significant risk indicators."]
)

analysis = {
    "timestamp": row["timestamp"], "sender": row["sender"], "subject": row["subject"],
    "verdict": row["verdict"], "attack_type": row["attack_type"], "risk_score": row["risk_score"],
    "severity": row["severity"], "breakdown": breakdown, "explanations": indicators,
    "url_findings": [], "sender_reasons": [], "attachment_findings": [],
    "ai_explanation": row["ai_explanation"] or "", "attack_chain": [],
    "recommended_actions": recommended_actions,
}

st.subheader("Preview")
st.json({"verdict": row["verdict"], "risk_score": row["risk_score"], "severity": row["severity"],
         "attack_type": row["attack_type"]})

pdf_bytes = build_pdf_report(analysis)
st.download_button("📥 Download PDF report", data=pdf_bytes, file_name=f"phishing_report_{row['id']}.pdf",
                    mime="application/pdf", type="primary")
