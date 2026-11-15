"""Security Dashboard — statistics computed live from the SQLite database."""
from __future__ import annotations

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from database.database import get_dashboard_stats
from utils.helpers import format_timestamp

st.set_page_config(page_title="Dashboard | AI Phishing Detector", page_icon="📊", layout="wide")
st.title("Security Dashboard")

stats = get_dashboard_stats()

if stats["total"] == 0:
    st.info("No analyses yet. Analyze an email first to populate the dashboard.")
    st.page_link("pages/1_Analyze_Email.py", label="Analyze an email", icon="🔍")
    st.stop()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total analyzed", stats["total"])
c2.metric("Phishing", stats["by_verdict"].get("Phishing", 0))
c3.metric("Spam", stats["by_verdict"].get("Spam", 0))
c4.metric("Legitimate", stats["by_verdict"].get("Legitimate", 0))
c5.metric("High/Critical", stats["high_critical"])

st.metric("Average risk score", stats["avg_score"])

st.divider()
col1, col2 = st.columns(2)

with col1:
    st.subheader("Verdict distribution")
    if stats["by_verdict"]:
        fig = px.pie(names=list(stats["by_verdict"].keys()), values=list(stats["by_verdict"].values()),
                      color=list(stats["by_verdict"].keys()),
                      color_discrete_map={"Phishing": "#e74c3c", "Spam": "#f39c12", "Legitimate": "#2ecc71"})
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("Severity distribution")
    if stats["by_severity"]:
        colors = {"Low": "#2ecc71", "Medium": "#f1c40f", "High": "#e67e22", "Critical": "#e74c3c"}
        labels = list(stats["by_severity"].keys())
        fig = go.Figure(go.Bar(x=labels, y=list(stats["by_severity"].values()),
                                marker_color=[colors.get(l, "#888") for l in labels]))
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10), yaxis_title="Count")
        st.plotly_chart(fig, use_container_width=True)

if stats["by_attack_type"]:
    st.subheader("Attack-type distribution (phishing emails only)")
    fig = go.Figure(go.Bar(
        x=list(stats["by_attack_type"].values()), y=list(stats["by_attack_type"].keys()), orientation="h",
        marker_color="#3b6fd9",
    ))
    fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10), xaxis_title="Count")
    st.plotly_chart(fig, use_container_width=True)

st.divider()
st.subheader("Recent analyses")
for row in stats["recent"]:
    icon = {"Phishing": "🔴", "Spam": "🟠", "Legitimate": "🟢"}.get(row["verdict"], "⚪")
    st.markdown(
        f"{icon} **{row['subject'] or '(no subject)'}** — {row['sender'] or 'unknown sender'} "
        f"— score **{row['risk_score']}/100** ({row['severity']}) — {format_timestamp(row['timestamp'])}"
    )
