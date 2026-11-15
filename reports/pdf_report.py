"""Generates a downloadable PDF security report for one analysis, using
ReportLab. No API keys or secrets are ever written into the report."""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem,
)

VERDICT_COLOR = {
    "Legitimate": colors.HexColor("#2ecc71"),
    "Spam": colors.HexColor("#f39c12"),
    "Phishing": colors.HexColor("#e74c3c"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", fontSize=18, leading=22, spaceAfter=6, textColor=colors.HexColor("#1a2733")))
    styles.add(ParagraphStyle(name="SectionHeader", fontSize=13, leading=16, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1a2733")))
    styles.add(ParagraphStyle(name="Body", fontSize=10, leading=14))
    styles.add(ParagraphStyle(name="Small", fontSize=8, leading=11, textColor=colors.grey))
    return styles


def build_pdf_report(analysis: dict) -> bytes:
    """
    analysis: a plain dict with keys -
        timestamp, sender, subject, verdict, attack_type, risk_score, severity,
        breakdown (list of {label, points, max_points}),
        explanations (list[str]), suspicious_indicators (list[str]),
        url_findings (list of dict: url, domain, risk_points, reasons),
        sender_reasons (list[str]),
        attachment_findings (list of dict: filename, risk_points, reasons),
        ai_explanation (str), attack_chain (list[str]),
        recommended_actions (list[str])
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
                             leftMargin=1.8 * cm, rightMargin=1.8 * cm)
    styles = _styles()
    story = []

    story.append(Paragraph("AI Phishing Detector — Security Report", styles["ReportTitle"]))
    story.append(Paragraph(f"Generated: {analysis.get('timestamp', '')}", styles["Small"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Email Information", styles["SectionHeader"]))
    info_data = [
        ["Sender", analysis.get("sender", "N/A")],
        ["Subject", analysis.get("subject", "N/A")],
    ]
    info_table = Table(info_data, colWidths=[3 * cm, 13 * cm])
    info_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f2f5")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Verdict", styles["SectionHeader"]))
    verdict = analysis.get("verdict", "Unknown")
    color = VERDICT_COLOR.get(verdict, colors.grey)
    verdict_data = [[verdict, f"{analysis.get('risk_score', 0)}/100", analysis.get("severity", ""), analysis.get("attack_type", "N/A")]]
    verdict_table = Table(verdict_data, colWidths=[4 * cm, 4 * cm, 4 * cm, 4 * cm],
                           style=[("FONTSIZE", (0, 0), (-1, -1), 11), ("ALIGN", (0, 0), (-1, -1), "CENTER")])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), color),
        ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    header_row = [["Verdict", "Risk Score", "Severity", "Attack Type"]]
    header_table = Table(header_row, colWidths=[4 * cm, 4 * cm, 4 * cm, 4 * cm])
    header_table.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8), ("TEXTCOLOR", (0, 0), (-1, -1), colors.grey)]))
    story.append(header_table)
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Risk Factor Breakdown", styles["SectionHeader"]))
    breakdown_rows = [["Factor", "Score"]]
    for b in analysis.get("breakdown", []):
        breakdown_rows.append([b["label"], f"{b['points']}/{b['max_points']}"])
    bt = Table(breakdown_rows, colWidths=[10 * cm, 6 * cm])
    bt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2733")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(bt)
    story.append(Spacer(1, 10))

    def bullet_section(title, items):
        story.append(Paragraph(title, styles["SectionHeader"]))
        if items:
            story.append(ListFlowable(
                [ListItem(Paragraph(str(i), styles["Body"])) for i in items],
                bulletType="bullet", leftIndent=14,
            ))
        else:
            story.append(Paragraph("None detected.", styles["Body"]))

    bullet_section("Why is this suspicious?", analysis.get("explanations", []))

    url_findings = analysis.get("url_findings", [])
    if url_findings:
        story.append(Paragraph("URL Analysis", styles["SectionHeader"]))
        rows = [["URL / Domain", "Risk"]]
        for f in url_findings:
            rows.append([f.get("url", "")[:70], f"{f.get('risk_points', 0)}/100"])
        ut = Table(rows, colWidths=[13 * cm, 3 * cm])
        ut.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2733")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ]))
        story.append(ut)
        story.append(Spacer(1, 6))

    bullet_section("Sender Analysis Notes", analysis.get("sender_reasons", []))

    attachment_findings = analysis.get("attachment_findings", [])
    if attachment_findings:
        story.append(Paragraph("Attachment Analysis", styles["SectionHeader"]))
        rows = [["Filename", "Risk"]]
        for f in attachment_findings:
            rows.append([f.get("filename", ""), f"{f.get('risk_points', 0)}/100"])
        at = Table(rows, colWidths=[13 * cm, 3 * cm])
        at.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2733")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ]))
        story.append(at)
        story.append(Spacer(1, 6))

    story.append(Paragraph("AI Explanation", styles["SectionHeader"]))
    story.append(Paragraph(analysis.get("ai_explanation", "Not available."), styles["Body"]))
    story.append(Spacer(1, 8))

    chain = analysis.get("attack_chain", [])
    if chain:
        story.append(Paragraph("Possible Attack Chain", styles["SectionHeader"]))
        story.append(Paragraph(" → ".join(chain), styles["Body"]))
        story.append(Spacer(1, 8))

    bullet_section("Recommended Actions", analysis.get("recommended_actions", []))

    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "This report was generated automatically by an AI-agent based phishing analysis "
        "prototype built for academic purposes. It combines rule-based static analysis, a "
        "trained ML classifier, and an AI-generated explanation. It is not a substitute for "
        "professional incident response or antivirus/malware analysis.",
        styles["Small"],
    ))

    doc.build(story)
    return buf.getvalue()
