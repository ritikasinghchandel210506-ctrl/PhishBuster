"""Analyze Email page: upload a .eml file or paste email fields manually."""
from __future__ import annotations

import streamlit as st

from agents.email_agent import EmailAgent
from agents.orchestrator import Orchestrator
from database.database import save_analysis
from utils.email_parser import EmailParseError
from utils.helpers import now_iso

st.set_page_config(page_title="Analyze Email | AI Phishing Detector", page_icon="🔍", layout="wide")
st.title("Analyze Email")
st.caption("Upload a `.eml` file or paste the email fields manually. Nothing is sent anywhere except, "
           "optionally, a short structured summary to Gemini for the plain-language explanation.")

email_agent = EmailAgent()
orchestrator = Orchestrator()

tab_upload, tab_manual = st.tabs(["Upload .eml file", "Paste email manually"])

parsed_email = None
input_source = None
filename = None

with tab_upload:
    uploaded = st.file_uploader("Choose a .eml file", type=["eml"], accept_multiple_files=False)
    if uploaded is not None:
        st.info(f"File: **{uploaded.name}** ({uploaded.size/1024:.1f} KB)")
        if st.button("Analyze uploaded email", type="primary", key="analyze_upload"):
            try:
                raw = uploaded.getvalue()
                parsed_email = email_agent.run_from_eml(raw)
                input_source = "eml"
                filename = uploaded.name
            except EmailParseError as exc:
                st.error(f"Could not parse this file: {exc}")

with tab_manual:
    with st.form("manual_email_form"):
        col1, col2 = st.columns(2)
        with col1:
            sender = st.text_input("From (e.g. 'Name <email@domain.com>')", placeholder="Alerts <support@example-secure.tk>")
        with col2:
            recipient = st.text_input("To", placeholder="you@example.com")
        subject = st.text_input("Subject", placeholder="Urgent: Verify your account")
        body = st.text_area("Email body", height=220, placeholder="Paste the full email body here...")
        submitted = st.form_submit_button("Analyze pasted email", type="primary")
    if submitted:
        if not body.strip():
            st.error("Please paste an email body before analyzing.")
        else:
            parsed_email = email_agent.run_from_manual(sender, recipient, subject, body)
            input_source = "manual"
            filename = None

st.divider()

if parsed_email is not None:
    with st.spinner("Running agent pipeline (email parsing → ML → sender/URL/attachment/content analysis → risk scoring → explanation)..."):
        result = orchestrator.analyze(parsed_email, use_gemini=True)

    for w in result.parse_warnings:
        st.warning(w)

    # Persist to DB
    breakdown_map = {b.factor: b.points for b in result.risk_result.breakdown}
    record = {
        "timestamp": now_iso(),
        "filename": filename,
        "sender": parsed_email.sender_raw or parsed_email.sender_email,
        "subject": parsed_email.subject,
        "verdict": result.risk_result.verdict,
        "attack_type": result.attack_result.attack_type if result.risk_result.verdict == "Phishing" else "N/A",
        "risk_score": result.risk_result.total_score,
        "severity": result.risk_result.severity,
        "ml_probability": result.ml_result.phishing_probability,
        "sender_risk": breakdown_map.get("sender_risk"),
        "url_risk": breakdown_map.get("url_risk"),
        "content_risk": breakdown_map.get("content_risk"),
        "attachment_risk": breakdown_map.get("attachment_risk"),
        "impersonation_risk": breakdown_map.get("impersonation"),
        "suspicious_indicators": result.risk_result.explanations,
        "ai_explanation": result.explanation.get("text", ""),
        "explanation_source": result.explanation.get("source", ""),
        "url_count": result.url_summary.get("count", 0),
        "attachment_count": result.attachment_summary.get("count", 0),
        "input_source": input_source or "manual",
    }
    analysis_id = save_analysis(record)

    st.session_state["last_analysis"] = {
        "result": result,
        "record": record,
        "analysis_id": analysis_id,
    }
    st.success("Analysis complete. Full details are on the **Results** page.")
    st.page_link("pages/2_Results.py", label="View full results", icon="📄")

    # Quick summary right here too
    v = result.risk_result.verdict
    icon = {"Phishing": "🔴", "Spam": "🟠", "Legitimate": "🟢"}.get(v, "⚪")
    st.markdown(f"### {icon} Verdict: **{v}**  |  Risk score: **{result.risk_result.total_score}/100**  |  Severity: **{result.risk_result.severity}**")
