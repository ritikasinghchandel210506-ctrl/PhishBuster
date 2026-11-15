"""Incident Response — "I Already Clicked" guidance."""
from __future__ import annotations

import streamlit as st

from agents.remediation_agent import RemediationAgent

st.set_page_config(page_title="Incident Response | AI Phishing Detector", page_icon="🚨", layout="wide")
st.title("I Already Clicked — What Do I Do Now?")
st.caption("Tell us what happened and get clear, defensive next steps. This tool never suggests "
           "offensive or retaliatory actions.")

agent = RemediationAgent()
scenarios = agent.all_scenarios()

labels = {k: v["label"] for k, v in scenarios.items()}
choice = st.radio("What happened?", list(labels.keys()), format_func=lambda k: labels[k])

st.divider()
scenario = agent.get_incident_response(choice)
st.subheader(f"Recommended actions: {scenario['label']}")
for i, action in enumerate(scenario["actions"], 1):
    st.markdown(f"{i}. {action}")

st.divider()
st.info(
    "If you believe your organization's systems or data may be affected, notify your IT/security "
    "team immediately, even if you are unsure. Reporting quickly is always the right call."
)
