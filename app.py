"""
AI Agents as Autonomous Phishing Email Detectors
Main Streamlit entry point (Home page).

Run with:  streamlit run app.py
"""
from __future__ import annotations

import streamlit as st

from database.database import init_db, get_dashboard_stats
from agents.ml_agent import MLAgent

st.set_page_config(
    page_title="AI Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

CUSTOM_CSS = """
<style>
.main-header { font-size: 2.2rem; font-weight: 700; color: #1a2733; margin-bottom: 0; }
.sub-header { color: #5a6b7a; font-size: 1.05rem; margin-top: 0; }
.metric-card {
    background: #ffffff; border: 1px solid #e3e7eb; border-radius: 10px;
    padding: 1rem 1.2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}
.agent-pill {
    display: inline-block; background: #eef2f7; color: #1a2733; padding: 4px 12px;
    border-radius: 16px; font-size: 0.82rem; margin: 3px; border: 1px solid #d7dde3;
}
footer {visibility: hidden;}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

st.markdown('<p class="main-header">🛡️ AI Agents as Autonomous Phishing Email Detectors</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">A multi-agent, explainable AI system for phishing &amp; spam email analysis</p>', unsafe_allow_html=True)
st.divider()

col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    st.subheader("What this project does")
    st.write(
        "This application analyzes emails using a coordinated team of specialized AI agents — "
        "not a single black-box model. Each agent inspects one dimension of the email "
        "(sender, URLs, attachments, language patterns, ML classification), and a deterministic "
        "**Risk Scoring Agent** combines their findings into a transparent 0-100 score. "
        "An **Explanation Agent** (Gemini, with a local fallback) then narrates the result in "
        "plain language — but it never changes the verdict."
    )
    st.markdown("**Pipeline:**")
    st.code(
        "Email  →  Email Parser  →  [ML Agent | Sender Agent | URL Agent | Attachment Agent | "
        "Content Agent]  →  Attack Classifier  →  Risk Engine  →  Verdict  →  Explanation Agent",
        language="text",
    )

    st.markdown("**Active agents:**")
    agent_names = [
        "Email Analysis Agent", "ML/NLP Detection Agent", "Attack-Type Classification Agent",
        "URL Analysis Agent", "Sender Analysis Agent", "Attachment Threat Analyzer",
        "Content/Suspicious Language Agent", "Risk Scoring Agent", "Explanation Agent",
        "Remediation Agent",
    ]
    st.markdown("".join(f'<span class="agent-pill">{a}</span>' for a in agent_names), unsafe_allow_html=True)

with col2:
    ml_agent = MLAgent()
    st.markdown("#### System Status")
    if ml_agent.is_ready:
        st.success("ML model: loaded ✅")
    else:
        st.error("ML model: not trained")
        st.caption("Run `python ml/train_model.py`")

    import os
    from dotenv import load_dotenv
    load_dotenv()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if gemini_key and gemini_key != "your_api_key_here":
        st.success("Gemini API: configured ✅")
    else:
        st.warning("Gemini API: not configured")
        st.caption("Local fallback explanations will be used. See .env.example")

with col3:
    st.markdown("#### Quick Stats")
    stats = get_dashboard_stats()
    st.metric("Emails analyzed", stats["total"])
    st.metric("High/Critical threats", stats["high_critical"])
    st.metric("Avg. risk score", stats["avg_score"])

st.divider()
st.subheader("Get started")
c1, c2, c3 = st.columns(3)
with c1:
    st.page_link("pages/1_Analyze_Email.py", label="Analyze an Email", icon="🔍")
with c2:
    st.page_link("pages/3_Dashboard.py", label="View Dashboard", icon="📊")
with c3:
    st.page_link("pages/7_Incident_Response.py", label="I Already Clicked", icon="🚨")

st.divider()
