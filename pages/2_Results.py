"""Results page — full breakdown of the most recent analysis."""
from __future__ import annotations

import streamlit as st
import plotly.graph_objects as go

from utils.helpers import escape_html, SEVERITY_COLORS, VERDICT_COLORS

st.set_page_config(page_title="Results | AI Phishing Detector", page_icon="📄", layout="wide")
st.title("Analysis Results")

state = st.session_state.get("last_analysis")
if not state:
    st.info("No analysis yet. Go to **Analyze Email** to run one.")
    st.page_link("pages/1_Analyze_Email.py", label="Analyze an email", icon="🔍")
    st.stop()

result = state["result"]
record = state["record"]
risk = result.risk_result
parsed = result.parsed_email

verdict_color = VERDICT_COLORS.get(risk.verdict, "#888")
severity_color = SEVERITY_COLORS.get(risk.severity, "#888")

c1, c2, c3, c4 = st.columns(4)
c1.markdown(f"**VERDICT**<br><span style='font-size:1.6rem;color:{verdict_color};font-weight:700'>{risk.verdict}</span>", unsafe_allow_html=True)
c2.markdown(f"**RISK SCORE**<br><span style='font-size:1.6rem;font-weight:700'>{risk.total_score}/100</span>", unsafe_allow_html=True)
c3.markdown(f"**SEVERITY**<br><span style='font-size:1.6rem;color:{severity_color};font-weight:700'>{risk.severity}</span>", unsafe_allow_html=True)
attack_type_display = result.attack_result.attack_type if risk.verdict == "Phishing" else "N/A"
c4.markdown(f"**ATTACK TYPE**<br><span style='font-size:1.3rem;font-weight:700'>{attack_type_display}</span>", unsafe_allow_html=True)

st.divider()

left, right = st.columns([1.3, 1])

with left:
    st.subheader("Risk Factors")
    labels = [b.label for b in risk.breakdown]
    points = [b.points for b in risk.breakdown]
    max_points = [b.max_points for b in risk.breakdown]
    fig = go.Figure()
    fig.add_trace(go.Bar(y=labels, x=max_points, orientation="h", name="Max", marker_color="#e3e7eb", showlegend=False))
    fig.add_trace(go.Bar(y=labels, x=points, orientation="h", name="Score", marker_color="#3b6fd9", showlegend=False))
    fig.update_layout(barmode="overlay", height=280, margin=dict(l=10, r=10, t=10, b=10),
                       xaxis_title="Points")
    st.plotly_chart(fig, use_container_width=True)
    for b in risk.breakdown:
        st.caption(f"**{b.label}**: {b.points}/{b.max_points}")

    st.subheader("Why is this suspicious?")
    for reason in risk.explanations:
        st.markdown(f"- {reason}")

    if risk.verdict == "Phishing" and result.attack_chain:
        st.subheader("Possible Attack Chain")
        st.caption("This shows a *potential* attack path based on detected indicators — not a confirmed real-world attack.")
        st.markdown(" → ".join(f"**{step}**" for step in result.attack_chain))

with right:
    st.subheader("AI Explanation")
    src = result.explanation.get("source")
    badge = "Gemini" if src == "gemini" else "Local fallback (Gemini not configured/unavailable)"
    st.caption(f"Source: {badge}")
    st.info(result.explanation.get("text", ""))

    st.subheader("Download Report")
    from reports.pdf_report import build_pdf_report
    pdf_analysis = {
        "timestamp": record["timestamp"],
        "sender": parsed.sender_raw or parsed.sender_email,
        "subject": parsed.subject,
        "verdict": risk.verdict,
        "attack_type": attack_type_display,
        "risk_score": risk.total_score,
        "severity": risk.severity,
        "breakdown": [{"label": b.label, "points": b.points, "max_points": b.max_points} for b in risk.breakdown],
        "explanations": risk.explanations,
        "url_findings": [{"url": f.url, "risk_points": f.risk_points} for f in result.url_summary.get("findings", [])],
        "sender_reasons": result.sender_finding.reasons,
        "attachment_findings": [{"filename": f.filename, "risk_points": f.risk_points} for f in result.attachment_summary.get("findings", [])],
        "ai_explanation": result.explanation.get("text", ""),
        "attack_chain": result.attack_chain,
        "recommended_actions": [
            "Do not click links or open attachments from this email if it is not legitimate.",
            "Verify the sender through a separate, trusted channel before acting on any request.",
            "Report this email to your IT/security team if received on a work account.",
        ] if risk.verdict != "Legitimate" else ["No action required — this email did not trigger significant risk indicators."],
    }
    pdf_bytes = build_pdf_report(pdf_analysis)
    st.download_button("Download PDF report", data=pdf_bytes, file_name=f"phishing_report_{state['analysis_id']}.pdf",
                        mime="application/pdf")

st.divider()

tabs = st.tabs(["Highlighted Content", "URL Analysis", "Sender Analysis", "Attachment Analysis"])

with tabs[0]:
    st.caption("Suspicious phrases are highlighted by category. Original content is preserved below in a separate view.")
    text = f"{parsed.subject}\n\n{parsed.combined_body}"
    matches = sorted(result.content_finding.matches, key=lambda m: m.start)
    category_colors = {
        "Urgency": "#ffe58f", "Threat": "#ffb3b3", "Credential Request": "#ff9999",
        "Financial Request": "#ffd8a8", "Impersonation": "#d0bfff", "OTP/Password Request": "#ff9999",
        "Account Suspension": "#ffb3b3",
    }
    if matches:
        html_parts = []
        cursor = 0
        for m in matches:
            if m.start < cursor:
                continue
            html_parts.append(escape_html(text[cursor:m.start]))
            color = category_colors.get(m.category, "#ffe58f")
            html_parts.append(
                f'<span style="background:{color};padding:1px 3px;border-radius:3px;" '
                f'title="{escape_html(m.category)}">{escape_html(text[m.start:m.end])}</span>'
            )
            cursor = m.end
        html_parts.append(escape_html(text[cursor:]))
        st.markdown(
            f'<div style="white-space:pre-wrap;line-height:1.6;border:1px solid #e3e7eb;'
            f'border-radius:8px;padding:14px;background:#fff;">{"".join(html_parts)}</div>',
            unsafe_allow_html=True,
        )
        st.caption("Legend: " + ", ".join(f"🟨 {c}" for c in result.content_finding.category_counts.keys()))
    else:
        st.markdown(
            f'<div style="white-space:pre-wrap;line-height:1.6;border:1px solid #e3e7eb;'
            f'border-radius:8px;padding:14px;background:#fff;">{escape_html(text)}</div>',
            unsafe_allow_html=True,
        )
        st.caption("No suspicious language patterns were matched.")

    with st.expander("View original, unmodified email content"):
        st.text(text)

with tabs[1]:
    urls = result.url_summary
    st.caption(urls.get("note", ""))
    if urls.get("count", 0) == 0:
        st.write("No URLs found in this email.")
    else:
        for f in urls["findings"]:
            with st.container(border=True):
                st.markdown(f"**{f.url}**")
                st.progress(min(100, f.risk_points) / 100, text=f"Risk: {f.risk_points}/100")
                for r in f.reasons:
                    st.markdown(f"- {r}")
                if not f.reasons:
                    st.caption("No red flags identified for this link.")

with tabs[2]:
    sf = result.sender_finding
    st.markdown(f"**Sender domain:** `{sf.sender_domain or 'N/A'}`")
    if sf.reply_to_domain:
        st.markdown(f"**Reply-To domain:** `{sf.reply_to_domain}`")
    st.markdown(f"**SPF:** {sf.spf_status}  |  **DKIM:** {sf.dkim_status}  |  **DMARC:** {sf.dmarc_status}")
    st.progress(min(100, sf.risk_points) / 100, text=f"Sender risk: {sf.risk_points}/100")
    for r in sf.reasons:
        st.markdown(f"- {r}")

with tabs[3]:
    atts = result.attachment_summary
    st.caption(atts.get("note", ""))
    if atts.get("count", 0) == 0:
        st.write("No attachments found in this email.")
    else:
        for f in atts["findings"]:
            with st.container(border=True):
                st.markdown(f"**{f.filename}** ({f.content_type}, {f.size_bytes} bytes)")
                st.progress(min(100, f.risk_points) / 100, text=f"Risk: {f.risk_points}/100")
                for r in f.reasons:
                    st.markdown(f"- {r}")
