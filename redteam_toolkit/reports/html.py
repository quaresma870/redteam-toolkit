"""
HTML report generator — self-contained, structured like a standard pentest
report: executive summary first, technical detail after. Visual style
matches the rest of this portfolio's dark-themed reports for consistency.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from redteam_toolkit.core.models import EngagementReport, Finding

_CSS = """
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;--accent:#4f8ef7;
--text:#e2e8f0;--muted:#64748b;--critical:#ef4444;--high:#f97316;
--medium:#f59e0b;--low:#3b82f6;--ok:#22c55e;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;padding:2rem;max-width:1100px;margin:0 auto}
h1{font-size:1.7rem;font-weight:700;color:var(--accent);margin-bottom:.25rem}
h2{font-size:1.1rem;font-weight:600;margin:1.5rem 0 .75rem}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:1rem}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{text-align:left;padding:.5rem .75rem;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)}
td{padding:.5rem .75rem;border-bottom:1px solid #1f2230;vertical-align:top}
tr:last-child td{border:none}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.25rem;margin-bottom:1.25rem}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700}
.CRITICAL{background:#3f1010;color:var(--critical)}
.HIGH{background:#3f1f08;color:var(--high)}
.MEDIUM{background:#3f2a00;color:var(--medium)}
.LOW{background:#0c1f3f;color:var(--low)}
.INFO{background:#1a1d27;color:var(--muted);border:1px solid var(--border)}
.scope-table td:first-child{color:var(--muted);width:160px}
.evidence{font-family:ui-monospace,monospace;font-size:.78rem;color:var(--muted);
  background:#0c0e14;padding:.4rem .6rem;border-radius:4px;display:block;margin-top:.3rem;
  white-space:pre-wrap;word-break:break-all}
.integrity-ok{color:var(--ok)}
.integrity-bad{color:var(--critical)}
footer{color:var(--muted);font-size:.75rem;margin-top:2rem;text-align:center}
</style>
"""

_RISK_BANDS = (
    (0.5, "CRITICAL", "Immediate action required — at least one critical-severity finding."),
    (0.0, "ELEVATED", "High-severity findings present — prioritise remediation."),
)


def _risk_posture(counts: dict[str, int]) -> tuple[str, str]:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL", "At least one critical-severity finding requires immediate attention."
    if counts.get("HIGH", 0) > 0:
        return "ELEVATED", "High-severity findings are present and should be prioritised."
    if counts.get("MEDIUM", 0) > 0:
        return "MODERATE", "Only medium-or-lower severity findings were identified."
    return "LOW", "No medium-or-higher severity findings were identified in this engagement."


def _group_by_target_and_category(findings: list[Finding]) -> dict:
    grouped: dict[str, dict[str, list[Finding]]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        grouped[f.target][f.category.value].append(f)
    return grouped


_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def render_html(report: EngagementReport) -> str:
    counts = report.counts_by_severity()
    findings = sorted(report.all_findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))
    risk_level, risk_text = _risk_posture(counts)

    scope_rows = "".join(f"<tr><td>Target pattern</td><td>{t}</td></tr>" for t in report.target_scope)
    summary_table = f"""
    <table class="scope-table">
      <tr><td>Engagement ID</td><td>{report.engagement_id}</td></tr>
      <tr><td>Client</td><td>{report.client}</td></tr>
      <tr><td>Authorized by</td><td>{report.authorized_by}</td></tr>
      <tr><td>Authorized window</td><td>{report.window_start} &rarr; {report.window_end}</td></tr>
      {scope_rows}
    </table>
    """

    severity_badges = "  ".join(
        f'<span class="badge {sev}">{counts.get(sev, 0)} {sev}</span>' for sev in _SEVERITY_ORDER
    )

    findings_rows = ""
    for f in findings:
        evidence_html = f'<div class="evidence">{_escape(f.evidence)}</div>' if f.evidence else ""
        remediation_html = f"<br><em>Remediation:</em> {_escape(f.remediation)}" if f.remediation else ""
        cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—"
        findings_rows += (
            f'<tr><td><span class="badge {f.severity.value}">{f.severity.value}</span></td>'
            f"<td>{f.target}</td><td>{f.category.value}</td><td>{f.module}</td>"
            f"<td>{_escape(f.title)}<br><span style='color:var(--muted);font-size:.82rem'>"
            f"{_escape(f.description)}</span>{remediation_html}{evidence_html}</td>"
            f"<td>{cvss}</td></tr>\n"
        )

    integrity_class = "integrity-ok" if report.audit_log_integrity_ok else "integrity-bad"
    integrity_text = "verified — no tampering detected" if report.audit_log_integrity_ok else "INTEGRITY CHECK FAILED"

    module_summary_rows = "".join(
        f"<tr><td>{mr.module}</td><td>{len(mr.findings)}</td>"
        f"<td>{mr.error or '—'}</td><td>{mr.duration_ms:.0f}ms</td></tr>"
        for mr in report.module_results
    )

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Engagement Report — {report.engagement_id}</title>{_CSS}</head><body>

<h1>🎯 Engagement Report</h1>
<p class="sub">{report.engagement_id} — generated {report.started_at.strftime('%Y-%m-%d %H:%M UTC')}</p>

<div class="card">
  <h2>Executive Summary</h2>
  <p style="margin-bottom:.75rem"><span class="badge {risk_level if risk_level != 'LOW' else 'INFO'}">{risk_level} RISK</span>
  &nbsp; {risk_text}</p>
  <p style="margin-bottom:.75rem">{severity_badges}</p>
  {summary_table}
</div>

<div class="card">
  <h2>Scope &amp; Authorization</h2>
  <p class="sub">This engagement was authorized for the scope and window shown above only.
  Any target outside that scope was refused by the toolkit's enforcement gate and is not
  reflected in the findings below.</p>
  <p>Audit log: <span class="{integrity_class}">{integrity_text}</span>
  &nbsp; ({report.audit_log_entry_count} recorded action(s))</p>
</div>

<div class="card">
  <h2>Modules Run</h2>
  <table>
    <tr><th>Module</th><th>Findings</th><th>Error</th><th>Duration</th></tr>
    {module_summary_rows or "<tr><td colspan='4' style='text-align:center;color:var(--muted)'>No modules run yet</td></tr>"}
  </table>
</div>

<div class="card">
  <h2>Technical Findings</h2>
  <table>
    <tr><th>Severity</th><th>Target</th><th>Category</th><th>Module</th><th>Finding</th><th>CVSS</th></tr>
    {findings_rows or "<tr><td colspan='6' style='text-align:center;color:var(--muted)'>No findings</td></tr>"}
  </table>
</div>

<footer>redteam-toolkit — Engagement Report — best-effort tooling, not a substitute for analyst review</footer>
<script type="application/json" id="report-data">{_safe_json_for_script_tag(report.to_dict())}</script>
</body></html>"""


def _safe_json_for_script_tag(data: dict) -> str:
    """Serialises data for embedding inside a <script> tag. A finding's
    evidence field can contain attacker-influenced content (e.g. the very
    XSS payload being reported on) — if it contains the literal sequence
    '</script', naive embedding lets it break out of the script tag and
    inject raw HTML into the report. Escaping the forward slash prevents
    the browser from recognising it as a tag close, without changing the
    JSON's meaning (JSON does not require '/' to be escaped, but allows it)."""
    return json.dumps(data, default=str).replace("</", "<\\/")


def _escape(text: str) -> str:
    if not text:
        return ""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def write_html(report: EngagementReport, path: str | Path) -> None:
    Path(path).write_text(render_html(report), encoding="utf-8")
