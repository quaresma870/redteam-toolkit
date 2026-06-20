from __future__ import annotations

import tempfile
from pathlib import Path

from redteam_toolkit.core.history import register_engagement, save_module_result
from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity


def _client(db: str):
    from fastapi.testclient import TestClient

    from redteam_toolkit.dashboard.app import create_app
    return TestClient(create_app(db))


class TestDashboardIndex:
    def test_lists_engagements(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["1.2.3.4"], "a", "b")
            register_engagement(db, "eng2", "Widgets", "Bob", ["5.6.7.8"], "c", "d")

            client = _client(db)
            r = client.get("/")
            assert r.status_code == 200
            assert "eng1" in r.text
            assert "eng2" in r.text

    def test_empty_state(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            client = _client(db)
            r = client.get("/")
            assert r.status_code == 200
            assert "No engagements" in r.text

    def test_shows_integrity_status(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["1.2.3.4"], "a", "b",
                                audit_log_integrity_ok=True, audit_log_entry_count=5)
            client = _client(db)
            r = client.get("/")
            assert "OK" in r.text


class TestDashboardEngagementDetail:
    def test_shows_findings(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["127.0.0.1"], "a", "b",
                                audit_log_integrity_ok=True, audit_log_entry_count=3)
            mr = ModuleResult(module="sqli_detection")
            mr.findings = [Finding(module="sqli_detection", title="Possible SQL injection",
                                   severity=Severity.CRITICAL, category=FindingCategory.ACTIVE,
                                   target="127.0.0.1", cvss_score=9.8)]
            save_module_result(db, "eng1", "127.0.0.1", mr)

            client = _client(db)
            r = client.get("/engagement/eng1")
            assert r.status_code == 200
            assert "Possible SQL injection" in r.text
            assert "9.8" in r.text

    def test_404_for_unknown_engagement(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            client = _client(db)
            r = client.get("/engagement/nonexistent")
            assert r.status_code == 404

    def test_finding_without_explicit_cvss_shows_rubric_score(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["example.com"], "a", "b")
            mr = ModuleResult(module="zone_transfer")
            mr.findings = [Finding(module="zone_transfer", title="Zone transfer ALLOWED",
                                   severity=Severity.HIGH, category=FindingCategory.RECON,
                                   target="example.com")]  # no cvss_score
            save_module_result(db, "eng1", "example.com", mr)

            client = _client(db)
            r = client.get("/engagement/eng1")
            assert "7.5" in r.text  # HIGH rubric value applied on render

    def test_finding_content_escaped_in_findings_table(self):
        """Regression test: a finding's title/target could in principle
        contain attacker-influenced content — must never render raw,
        consistent with the same fix applied to the HTML report generator."""
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["127.0.0.1"], "a", "b")
            mr = ModuleResult(module="xss_detection")
            mr.findings = [Finding(module="xss_detection", title="<script>alert(1)</script>",
                                   severity=Severity.HIGH, category=FindingCategory.ACTIVE,
                                   target="127.0.0.1", cvss_score=7.4)]
            save_module_result(db, "eng1", "127.0.0.1", mr)

            client = _client(db)
            r = client.get("/engagement/eng1")
            assert "<script>alert(1)</script>" not in r.text
            assert "&lt;script&gt;" in r.text

    def test_no_findings_shows_empty_state(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["1.2.3.4"], "a", "b")
            client = _client(db)
            r = client.get("/engagement/eng1")
            assert r.status_code == 200
            assert "No findings" in r.text


class TestDashboardApi:
    def test_api_engagements_list(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["1.2.3.4"], "a", "b")
            client = _client(db)
            r = client.get("/api/engagements")
            assert r.status_code == 200
            data = r.json()
            assert len(data) == 1
            assert data[0]["engagement_id"] == "eng1"

    def test_api_engagement_detail(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["1.2.3.4"], "a", "b")
            client = _client(db)
            r = client.get("/api/engagement/eng1")
            assert r.status_code == 200
            assert r.json()["client"] == "Acme"

    def test_api_engagement_detail_404(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            client = _client(db)
            r = client.get("/api/engagement/nonexistent")
            assert r.status_code == 404
