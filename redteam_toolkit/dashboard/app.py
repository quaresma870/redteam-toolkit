"""
redteam-toolkit web dashboard — FastAPI, read-only engagement history.
Start with: redteam-toolkit serve --db engagements.db

Reconstructs reports purely from the database (see
core/history.build_report_from_db) — never touches the original
authorization.yml or audit log files, so this can run as a standalone
service with only the history database.

⚠️ Not authenticated by default. Do not expose this beyond localhost
without putting an auth layer in front of it — same caution as every
other dashboard in this portfolio.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from redteam_toolkit.core.history import build_report_from_db, list_engagements

_CSS = """
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;--accent:#4f8ef7;
--text:#e2e8f0;--muted:#64748b;--critical:#ef4444;--high:#f97316;
--medium:#f59e0b;--low:#3b82f6;--ok:#22c55e;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;padding:2rem;max-width:1100px;margin:0 auto}
h1{font-size:1.6rem;font-weight:700;color:var(--accent);margin-bottom:.25rem}
h2{font-size:1rem;font-weight:600;margin-bottom:.75rem}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{text-align:left;padding:.5rem .75rem;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)}
td{padding:.5rem .75rem;border-bottom:1px solid #1f2230}
tr:last-child td{border:none}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.25rem;margin-bottom:1rem}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700}
.CRITICAL{background:#3f1010;color:var(--critical)}
.HIGH{background:#3f1f08;color:var(--high)}
.MEDIUM{background:#3f2a00;color:var(--medium)}
.LOW{background:#0c1f3f;color:var(--low)}
.INFO{background:#1a1d27;color:var(--muted)}
.integrity-ok{color:var(--ok)}
.integrity-bad{color:var(--critical)}
footer{color:var(--muted);font-size:.75rem;margin-top:2rem;text-align:center}
</style>
"""


def _escape(text: str) -> str:
    """Escapes finding content before rendering — titles/targets are mostly
    module-controlled, but defense in depth matters in a security tool's
    own dashboard, and target strings do originate from CLI input."""
    if not text:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def create_app(db_path: str) -> FastAPI:
    app = FastAPI(title="redteam-toolkit Dashboard")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        engagements = list_engagements(db_path)
        rows = ""
        for e in engagements:
            integrity = e.get("audit_log_integrity_ok")
            integrity_html = (
                '<span class="integrity-ok">OK</span>' if integrity
                else '<span class="integrity-bad">TAMPERED</span>' if integrity is not None
                else '<span style="color:var(--muted)">—</span>'
            )
            rows += (
                f'<tr><td><a href="/engagement/{_escape(e["engagement_id"])}">{_escape(e["engagement_id"])}</a></td>'
                f'<td>{_escape(e.get("client")) or "—"}</td><td>{_escape(e.get("authorized_by")) or "—"}</td>'
                f'<td>{integrity_html}</td></tr>\n'
            )
        if not rows:
            rows = (
                '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:2rem">'
                "No engagements recorded yet.</td></tr>"
            )

        return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>redteam-toolkit Dashboard</title>{_CSS}</head><body>
<h1>🎯 redteam-toolkit</h1>
<p class="sub">Engagement history — <a href="/api/engagements">JSON API</a></p>
<div class="card">
<h2>Engagements</h2>
<table><tr><th>Engagement ID</th><th>Client</th><th>Authorized by</th><th>Audit log</th></tr>
{rows}</table></div>
<footer>redteam-toolkit Dashboard — read-only, not authenticated by default</footer>
</body></html>""")

    @app.get("/engagement/{engagement_id}", response_class=HTMLResponse)
    async def engagement_detail(engagement_id: str):
        report = build_report_from_db(db_path, engagement_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Engagement not found")

        counts = report.counts_by_severity()
        badges = "  ".join(
            f'<span class="badge {sev}">{counts.get(sev, 0)} {sev}</span>'
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )

        findings_rows = ""
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for f in sorted(report.all_findings, key=lambda x: order.index(x.severity.value)):
            cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—"
            findings_rows += (
                f'<tr><td><span class="badge {f.severity.value}">{f.severity.value}</span></td>'
                f"<td>{_escape(f.target)}</td><td>{_escape(f.module)}</td>"
                f"<td>{_escape(f.title)}</td><td>{cvss}</td></tr>\n"
            )

        integrity = report.audit_log_integrity_ok
        integrity_html = (
            '<span class="integrity-ok">verified — no tampering detected</span>' if integrity
            else '<span class="integrity-bad">INTEGRITY CHECK FAILED</span>' if integrity is not None
            else '<span style="color:var(--muted)">not available</span>'
        )

        return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>{_escape(engagement_id)} — redteam-toolkit Dashboard</title>{_CSS}</head><body>
<p><a href="/">← All engagements</a></p>
<h1>🎯 {_escape(engagement_id)}</h1>
<p class="sub">{_escape(report.client)} — authorized by {_escape(report.authorized_by)}</p>
<div class="card">
<h2>Severity Summary</h2>
<p>{badges}</p>
</div>
<div class="card">
<h2>Scope &amp; Window</h2>
<p>Targets: {_escape(", ".join(report.target_scope))}</p>
<p>Window: {report.window_start} &rarr; {report.window_end}</p>
<p>Audit log: {integrity_html} ({report.audit_log_entry_count} recorded action(s))</p>
</div>
<div class="card">
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Target</th><th>Module</th><th>Title</th><th>CVSS</th></tr>
{findings_rows or '<tr><td colspan="5" style="text-align:center;color:var(--muted)">No findings</td></tr>'}</table>
</div>
<footer>redteam-toolkit Dashboard</footer>
</body></html>""")

    @app.get("/api/engagements")
    async def api_engagements():
        return JSONResponse(list_engagements(db_path))

    @app.get("/api/engagement/{engagement_id}")
    async def api_engagement_detail(engagement_id: str):
        report = build_report_from_db(db_path, engagement_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Engagement not found")
        return JSONResponse(report.to_dict())

    return app
