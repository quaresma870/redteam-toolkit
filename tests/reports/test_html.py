from __future__ import annotations

import tempfile
from pathlib import Path

from redteam_toolkit.core.models import (
    EngagementReport,
    Finding,
    FindingCategory,
    ModuleResult,
    Severity,
)


def _sample_report(**overrides) -> EngagementReport:
    defaults = dict(
        engagement_id="test-eng", target_scope=["127.0.0.1", "*.example.com"],
        authorized_by="Jane Doe, CISO", client="Acme Corp",
        window_start="2026-01-01T00:00:00Z", window_end="2026-01-07T23:59:59Z",
        audit_log_integrity_ok=True, audit_log_entry_count=10,
    )
    defaults.update(overrides)
    return EngagementReport(**defaults)


class TestRenderHtml:
    def test_self_contained_no_external_files(self):
        """Acceptance criteria allows a CDN chart library, but this report
        doesn't even use one — fully self-contained with zero external
        requests of any kind."""
        from redteam_toolkit.reports.html import render_html

        html = render_html(_sample_report())
        assert "<link" not in html
        assert "src=" not in html  # no external scripts/images/stylesheets at all

    def test_includes_scope_and_window(self):
        from redteam_toolkit.reports.html import render_html

        html = render_html(_sample_report())
        assert "127.0.0.1" in html
        assert "2026-01-01T00:00:00Z" in html
        assert "2026-01-07T23:59:59Z" in html

    def test_includes_client_and_authorized_by(self):
        from redteam_toolkit.reports.html import render_html

        html = render_html(_sample_report())
        assert "Acme Corp" in html
        assert "Jane Doe, CISO" in html

    def test_critical_finding_shows_critical_risk_posture(self):
        from redteam_toolkit.reports.html import render_html

        report = _sample_report()
        mr = ModuleResult(module="sqli_detection")
        mr.findings = [Finding(module="sqli_detection", title="SQLi found", severity=Severity.CRITICAL,
                               category=FindingCategory.ACTIVE, target="127.0.0.1", cvss_score=9.8)]
        report.module_results = [mr]

        html = render_html(report)
        assert "CRITICAL RISK" in html
        assert "SQLi found" in html
        assert "9.8" in html

    def test_no_findings_low_risk_posture(self):
        from redteam_toolkit.reports.html import render_html

        html = render_html(_sample_report())
        assert "LOW RISK" in html

    def test_audit_log_integrity_shown_ok(self):
        from redteam_toolkit.reports.html import render_html

        html = render_html(_sample_report(audit_log_integrity_ok=True))
        assert "verified" in html.lower()

    def test_audit_log_integrity_shown_failed(self):
        from redteam_toolkit.reports.html import render_html

        html = render_html(_sample_report(audit_log_integrity_ok=False))
        assert "FAILED" in html

    def test_findings_sorted_by_severity(self):
        from redteam_toolkit.reports.html import render_html

        report = _sample_report()
        mr = ModuleResult(module="x")
        mr.findings = [
            Finding(module="x", title="Low one", severity=Severity.LOW, category=FindingCategory.RECON,
                   target="h", cvss_score=3.0),
            Finding(module="x", title="Critical one", severity=Severity.CRITICAL, category=FindingCategory.ACTIVE,
                   target="h", cvss_score=9.8),
        ]
        report.module_results = [mr]

        html = render_html(report)
        assert html.index("Critical one") < html.index("Low one")

    def test_html_escapes_finding_content(self):
        """Findings could contain attacker-influenced strings (e.g. a
        reflected XSS payload as evidence) — must never be rendered raw."""
        from redteam_toolkit.reports.html import render_html

        report = _sample_report()
        mr = ModuleResult(module="xss_detection")
        mr.findings = [Finding(module="xss_detection", title="XSS", severity=Severity.HIGH,
                               category=FindingCategory.ACTIVE, target="h",
                               evidence="<script>alert(1)</script>", cvss_score=7.4)]
        report.module_results = [mr]

        html = render_html(report)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_modules_run_section_present(self):
        from redteam_toolkit.reports.html import render_html

        report = _sample_report()
        mr = ModuleResult(module="port_scanner", duration_ms=250)
        report.module_results = [mr]

        html = render_html(report)
        assert "port_scanner" in html
        assert "250" in html


class TestWriteHtml:
    def test_writes_file(self):
        from redteam_toolkit.reports.html import write_html

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.html"
            write_html(_sample_report(), path)
            assert path.exists()
            assert "test-eng" in path.read_text()
