"""Analysis History — browse and inspect previous analyses."""
from __future__ import annotations

import json
import streamlit as st

from database.database import get_history, get_analysis_by_id
from utils.helpers import format_timestamp

st.set_page_config(page_title="History | AI Phishing Detector", page_icon="🕓", layout="wide")
st.title("Analysis History")

history = get_history(limit=300)

if not history:
    st.info("No analyses yet.")
    st.page_link("pages/1_Analyze_Email.py", label="Analyze an email", icon="🔍")
    st.stop()

verdict_filter = st.multiselect("Filter by verdict", ["Phishing", "Spam", "Legitimate"], default=[])
filtered = [h for h in history if not verdict_filter or h["verdict"] in verdict_filter]

st.caption(f"Showing {len(filtered)} of {len(history)} analyses.")

for row in filtered:
    icon = {"Phishing": "🔴", "Spam": "🟠", "Legitimate": "🟢"}.get(row["verdict"], "⚪")
    with st.expander(f"{icon} #{row['id']} — {row['subject'] or '(no subject)'} — {row['verdict']} "
                      f"({row['risk_score']}/100, {row['severity']}) — {format_timestamp(row['timestamp'])}"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**Sender:** {row['sender'] or 'N/A'}")
            st.markdown(f"**Attack type:** {row['attack_type'] or 'N/A'}")
            st.markdown(f"**ML phishing probability:** {row['ml_probability']}")
            st.markdown(f"**Input source:** {row['input_source']}")
            if row["filename"]:
                st.markdown(f"**File:** {row['filename']}")
        with c2:
            st.markdown(f"**Sender risk:** {row['sender_risk']}/20")
            st.markdown(f"**URL risk:** {row['url_risk']}/20")
            st.markdown(f"**Content risk:** {row['content_risk']}/15")
            st.markdown(f"**Attachment risk:** {row['attachment_risk']}/10")
            st.markdown(f"**Impersonation risk:** {row['impersonation_risk']}/10")

        st.markdown("**Suspicious indicators:**")
        try:
            indicators = json.loads(row["suspicious_indicators"] or "[]")
        except json.JSONDecodeError:
            indicators = []
        for i in indicators:
            st.markdown(f"- {i}")

        st.markdown("**AI Explanation:**")
        st.info(row["ai_explanation"] or "N/A")
