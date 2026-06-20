from __future__ import annotations

import tempfile
from pathlib import Path

from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity


def _make_result(module: str, n_findings: int = 1, severity=Severity.INFO) -> ModuleResult:
    mr = ModuleResult(module=module, duration_ms=100)
    mr.findings = [
        Finding(module=module, title=f"Finding {i}", severity=severity,
               category=FindingCategory.RECON, target="127.0.0.1")
        for i in range(n_findings)
    ]
    return mr


class TestRegisterEngagement:
    def test_creates_engagement(self):
        from redteam_toolkit.core.history import get_engagement, register_engagement

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["127.0.0.1"], "2026-01-01", "2026-01-07")
            eng = get_engagement(db, "eng1")
            assert eng["client"] == "Acme"
            assert eng["authorized_by"] == "Jane"

    def test_upsert_updates_existing(self):
        from redteam_toolkit.core.history import get_engagement, register_engagement

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["127.0.0.1"], "2026-01-01", "2026-01-07")
            register_engagement(db, "eng1", "Acme Renamed", "Jane", ["127.0.0.1"], "2026-01-01", "2026-01-07")
            eng = get_engagement(db, "eng1")
            assert eng["client"] == "Acme Renamed"

    def test_integrity_snapshot_persisted(self):
        from redteam_toolkit.core.history import get_engagement, register_engagement

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(
                db, "eng1", "Acme", "Jane", ["127.0.0.1"], "2026-01-01", "2026-01-07",
                audit_log_integrity_ok=True, audit_log_entry_count=10,
            )
            eng = get_engagement(db, "eng1")
            assert eng["audit_log_integrity_ok"] == 1
            assert eng["audit_log_entry_count"] == 10

    def test_get_nonexistent_returns_none(self):
        from redteam_toolkit.core.history import get_engagement

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            assert get_engagement(db, "nonexistent") is None

    def test_old_schema_database_migrates_automatically(self):
        """Backward compatibility: a database created before the integrity
        columns existed must still work with the new code."""
        import sqlite3

        from redteam_toolkit.core.history import get_engagement, register_engagement

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "old.db")
            conn = sqlite3.connect(db)
            conn.executescript("""
                CREATE TABLE engagements (
                    engagement_id TEXT PRIMARY KEY, client TEXT, authorized_by TEXT,
                    target_scope TEXT, window_start TEXT, window_end TEXT
                );
            """)
            conn.execute(
                "INSERT INTO engagements VALUES ('old-eng', 'OldCo', 'Bob', '[\"1.2.3.4\"]', 'a', 'b')"
            )
            conn.commit()
            conn.close()

            eng = get_engagement(db, "old-eng")
            assert eng["client"] == "OldCo"
            assert eng["audit_log_integrity_ok"] is None

            register_engagement(db, "new-eng", "NewCo", "Alice", ["5.6.7.8"], "c", "d")
            assert get_engagement(db, "new-eng")["client"] == "NewCo"


class TestSaveAndLoadModuleResults:
    def test_save_and_reload(self):
        from redteam_toolkit.core.history import load_module_results, save_module_result

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            save_module_result(db, "eng1", "127.0.0.1", _make_result("port_scanner", 2))

            results = load_module_results(db, "eng1")
            assert len(results) == 1
            assert results[0].module == "port_scanner"
            assert len(results[0].findings) == 2

    def test_multiple_modules_kept_separate(self):
        from redteam_toolkit.core.history import load_module_results, save_module_result

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            save_module_result(db, "eng1", "127.0.0.1", _make_result("port_scanner", 1))
            save_module_result(db, "eng1", "127.0.0.1", _make_result("sqli_detection", 1, Severity.CRITICAL))

            results = load_module_results(db, "eng1")
            modules = {mr.module for mr in results}
            assert modules == {"port_scanner", "sqli_detection"}

    def test_same_module_multiple_runs_combined(self):
        """Running the same module twice (e.g. against two targets in
        separate invocations) must combine findings under one ModuleResult."""
        from redteam_toolkit.core.history import load_module_results, save_module_result

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            save_module_result(db, "eng1", "host1", _make_result("port_scanner", 1))
            save_module_result(db, "eng1", "host2", _make_result("port_scanner", 1))

            results = load_module_results(db, "eng1")
            assert len(results) == 1
            assert len(results[0].findings) == 2
            assert results[0].duration_ms == 200  # both runs' durations summed

    def test_engagement_isolation(self):
        """Findings for one engagement must never leak into another."""
        from redteam_toolkit.core.history import load_module_results, save_module_result

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            save_module_result(db, "eng1", "127.0.0.1", _make_result("port_scanner", 1))
            save_module_result(db, "eng2", "127.0.0.1", _make_result("port_scanner", 5))

            results1 = load_module_results(db, "eng1")
            results2 = load_module_results(db, "eng2")
            assert len(results1[0].findings) == 1
            assert len(results2[0].findings) == 5

    def test_no_results_returns_empty_list(self):
        from redteam_toolkit.core.history import load_module_results

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            assert load_module_results(db, "nonexistent") == []

    def test_error_preserved(self):
        from redteam_toolkit.core.history import load_module_results, save_module_result

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            mr = ModuleResult(module="cve_correlation", error="network timeout", duration_ms=50)
            save_module_result(db, "eng1", "127.0.0.1", mr)

            results = load_module_results(db, "eng1")
            assert results[0].error == "network timeout"


class TestBuildReportFromDb:
    def test_reconstructs_full_report(self):
        from redteam_toolkit.core.history import (
            build_report_from_db,
            register_engagement,
            save_module_result,
        )

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(
                db, "eng1", "Acme", "Jane", ["127.0.0.1"], "2026-01-01", "2026-01-07",
                audit_log_integrity_ok=True, audit_log_entry_count=5,
            )
            save_module_result(db, "eng1", "127.0.0.1", _make_result("port_scanner", 1))

            report = build_report_from_db(db, "eng1")
            assert report.engagement_id == "eng1"
            assert report.client == "Acme"
            assert report.audit_log_integrity_ok is True
            assert report.audit_log_entry_count == 5
            assert len(report.all_findings) == 1

    def test_nonexistent_engagement_returns_none(self):
        from redteam_toolkit.core.history import build_report_from_db

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            assert build_report_from_db(db, "nonexistent") is None

    def test_findings_without_explicit_cvss_get_rubric_score(self):
        """The exact scenario this matters for: zone_transfer's HIGH
        finding never sets cvss_score explicitly — confirms the rubric
        fallback is applied when the report is reconstructed from the DB."""
        from redteam_toolkit.core.history import (
            build_report_from_db,
            register_engagement,
            save_module_result,
        )

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["example.com"], "a", "b")
            mr = ModuleResult(module="zone_transfer")
            mr.findings = [Finding(module="zone_transfer", title="Zone transfer ALLOWED on ns1",
                                   severity=Severity.HIGH, category=FindingCategory.RECON,
                                   target="example.com")]  # no cvss_score set
            save_module_result(db, "eng1", "example.com", mr)

            report = build_report_from_db(db, "eng1")
            assert report.all_findings[0].cvss_score == 7.5  # HIGH rubric value


class TestListEngagements:
    def test_lists_all_registered(self):
        from redteam_toolkit.core.history import list_engagements, register_engagement

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["1.2.3.4"], "a", "b")
            register_engagement(db, "eng2", "Widgets", "Bob", ["5.6.7.8"], "c", "d")
            engs = list_engagements(db)
            assert len(engs) == 2

    def test_empty_database(self):
        from redteam_toolkit.core.history import list_engagements

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            assert list_engagements(db) == []
