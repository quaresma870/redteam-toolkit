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
        engagement_id="test-eng", target_scope=["127.0.0.1"],
        authorized_by="Jane Doe, CISO", client="Acme Corp",
        window_start="2026-01-01T00:00:00Z", window_end="2026-01-07T23:59:59Z",
        audit_log_integrity_ok=True, audit_log_entry_count=10,
    )
    defaults.update(overrides)
    return EngagementReport(**defaults)


class TestWritePdf:
    def test_produces_valid_pdf(self):
        from redteam_toolkit.reports.pdf import write_pdf

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.pdf"
            write_pdf(_sample_report(), path)

            assert path.exists()
            with open(path, "rb") as f:
                header = f.read(5)
            assert header == b"%PDF-"

    def test_no_headless_browser_dependency(self):
        """Confirms the PDF generator doesn't import anything that would
        require a headless browser (Chromium/wkhtmltopdf) — reportlab is
        pure-Python with no such runtime dependency."""
        import ast

        import redteam_toolkit.reports.pdf as pdf_module

        source = Path(pdf_module.__file__).read_text()
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])

        forbidden = {"playwright", "selenium", "pyppeteer"}
        assert not (imported_modules & forbidden)

    def test_produces_nonempty_file_with_findings(self):
        from redteam_toolkit.reports.pdf import write_pdf

        report = _sample_report()
        mr = ModuleResult(module="sqli_detection")
        mr.findings = [Finding(module="sqli_detection", title="SQL injection found", severity=Severity.CRITICAL,
                               category=FindingCategory.ACTIVE, target="127.0.0.1",
                               description="Database error signature observed.",
                               remediation="Use parameterised queries.", cvss_score=9.8)]
        report.module_results = [mr]

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.pdf"
            write_pdf(report, path)
            # A report with content should be meaningfully larger than an
            # empty one — loose sanity check that content was actually written.
            assert path.stat().st_size > 2000

    def test_handles_no_findings(self):
        from redteam_toolkit.reports.pdf import write_pdf

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.pdf"
            write_pdf(_sample_report(), path)  # no module_results at all
            assert path.exists()

    def test_handles_special_characters_in_evidence(self):
        """Findings may contain HTML-special characters (e.g. raw XSS
        payloads as evidence) — must not break PDF generation."""
        from redteam_toolkit.reports.pdf import write_pdf

        report = _sample_report()
        mr = ModuleResult(module="xss_detection")
        mr.findings = [Finding(module="xss_detection", title="XSS", severity=Severity.HIGH,
                               category=FindingCategory.ACTIVE, target="h",
                               evidence="<script>alert(1)</script> & 'quotes' \"here\"",
                               cvss_score=7.4)]
        report.module_results = [mr]

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.pdf"
            write_pdf(report, path)  # must not raise
            assert path.exists()

    def test_multiple_findings_all_severities(self):
        from redteam_toolkit.reports.pdf import write_pdf

        report = _sample_report()
        mr = ModuleResult(module="x")
        mr.findings = [
            Finding(module="x", title=f"{sev.value} finding", severity=sev,
                   category=FindingCategory.RECON, target="h", cvss_score=1.0)
            for sev in Severity
        ]
        report.module_results = [mr]

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.pdf"
            write_pdf(report, path)
            assert path.exists()
