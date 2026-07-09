"""
PDF report generator — built directly with reportlab (pure-Python,
no Cairo/Pango/headless-browser system dependencies), with the same
content sections as the HTML report: executive summary, scope &
authorization, modules run, technical findings.

reportlab was chosen specifically to avoid a headless-browser dependency
(no Chromium/wkhtmltopdf) and the heavier system libraries weasyprint
needs (Cairo/Pango) — `pip install reportlab` is sufficient anywhere.
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from redteam_toolkit.core.models import EngagementReport

_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#ef4444"),
    "HIGH": colors.HexColor("#f97316"),
    "MEDIUM": colors.HexColor("#f59e0b"),
    "LOW": colors.HexColor("#3b82f6"),
    "INFO": colors.HexColor("#64748b"),
}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _risk_posture(counts: dict[str, int]) -> tuple[str, str]:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL", "At least one critical-severity finding requires immediate attention."
    if counts.get("HIGH", 0) > 0:
        return "ELEVATED", "High-severity findings are present and should be prioritised."
    if counts.get("MEDIUM", 0) > 0:
        return "MODERATE", "Only medium-or-lower severity findings were identified."
    return "LOW", "No medium-or-higher severity findings were identified in this engagement."


def write_pdf(report: EngagementReport, path: str | Path) -> None:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("RTKTitle", parent=styles["Title"], textColor=colors.HexColor("#1d4ed8"))
    h2_style = ParagraphStyle("RTKHeading", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
    body_style = styles["BodyText"]
    small_style = ParagraphStyle("RTKSmall", parent=styles["BodyText"], fontSize=8, textColor=colors.grey)

    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"Engagement Report — {report.engagement_id}",
        author=report.authorized_by,
        subject=f"Penetration test report for {report.client}",
    )

    counts = report.counts_by_severity()
    risk_level, risk_text = _risk_posture(counts)
    findings = sorted(report.all_findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))

    elements = []
    elements.append(Paragraph("🎯 Engagement Report", title_style))
    elements.append(Paragraph(
        f"{report.engagement_id} — generated {report.started_at.strftime('%Y-%m-%d %H:%M UTC')}", small_style,
    ))
    elements.append(Spacer(1, 12))

    # Executive summary
    elements.append(Paragraph("Executive Summary", h2_style))
    elements.append(Paragraph(f"<b>Risk posture: {risk_level}</b> — {risk_text}", body_style))
    elements.append(Spacer(1, 6))

    sev_table_data = [["Severity", "Count"]] + [[s, str(counts.get(s, 0))] for s in _SEVERITY_ORDER]
    sev_table = Table(sev_table_data, colWidths=[8 * cm, 4 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 12))

    # Scope & Authorization
    elements.append(Paragraph("Scope &amp; Authorization", h2_style))
    scope_data = [
        ["Engagement ID", report.engagement_id],
        ["Client", report.client],
        ["Authorized by", report.authorized_by],
        ["Window", f"{report.window_start} → {report.window_end}"],
        ["Target scope", ", ".join(report.target_scope)],
    ]
    scope_table = Table(scope_data, colWidths=[4 * cm, 12 * cm])
    scope_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(scope_table)
    elements.append(Spacer(1, 6))

    integrity_text = (
        "verified — no tampering detected" if report.audit_log_integrity_ok
        else "INTEGRITY CHECK FAILED"
    )
    elements.append(Paragraph(
        f"Audit log: {integrity_text} ({report.audit_log_entry_count} recorded action(s))", body_style,
    ))
    elements.append(Spacer(1, 12))

    # Modules run
    elements.append(Paragraph("Modules Run", h2_style))
    if report.module_results:
        module_data = [["Module", "Findings", "Error", "Duration"]]
        for mr in report.module_results:
            module_data.append([mr.module, str(len(mr.findings)), mr.error or "—", f"{mr.duration_ms:.0f}ms"])
        module_table = Table(module_data, colWidths=[5 * cm, 3 * cm, 5 * cm, 3 * cm])
        module_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elements.append(module_table)
    else:
        elements.append(Paragraph("No modules run yet.", body_style))
    elements.append(Spacer(1, 12))

    # Technical findings
    elements.append(Paragraph("Technical Findings", h2_style))
    if findings:
        for f in findings:
            sev_color = _SEVERITY_COLORS.get(f.severity.value, colors.grey)
            status = f.extra.get("status", "open") if f.extra else "open"
            status_reason = f.extra.get("status_reason") if f.extra else None
            header = Table(
                [[f.severity.value, f.target, f.category.value, f.module,
                  f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—", status]],
                colWidths=[2.2 * cm, 3.3 * cm, 2.2 * cm, 3.3 * cm, 1.5 * cm, 2.5 * cm],
            )
            header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), sev_color),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ]))
            elements.append(header)
            elements.append(Paragraph(f"<b>{_escape(f.title)}</b>", body_style))
            if f.description:
                elements.append(Paragraph(_escape(f.description), small_style))
            if f.remediation:
                elements.append(Paragraph(f"<i>Remediation:</i> {_escape(f.remediation)}", small_style))
            if f.evidence:
                elements.append(Paragraph(f"<font face='Courier' size=7>{_escape(f.evidence[:300])}</font>", small_style))
            if status_reason:
                elements.append(Paragraph(f"<i>Disposition ({status}):</i> {_escape(status_reason)}", small_style))
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("No findings.", body_style))

    elements.append(Spacer(1, 16))
    elements.append(Paragraph(
        "redteam-toolkit — Engagement Report — best-effort tooling, not a substitute for analyst review",
        small_style,
    ))

    doc.build(elements)


def _escape(text: str) -> str:
    if not text:
        return ""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
