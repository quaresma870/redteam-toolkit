from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from redteam_toolkit.core.history import register_engagement, save_module_result
from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity


def _result(module: str, findings: list[Finding]) -> ModuleResult:
    return ModuleResult(module=module, findings=findings)


def _finding(module: str, title: str, severity=Severity.CRITICAL, target="example.com") -> Finding:
    return Finding(module=module, title=title, severity=severity, category=FindingCategory.ACTIVE, target=target)


class TestSetAndGetStatus:
    def test_no_disposition_returns_none(self):
        from redteam_toolkit.core.status import get_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            assert get_status(db, "eng1", "some:key:here") is None

    def test_set_then_get_roundtrips(self):
        from redteam_toolkit.core.status import get_status, set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            set_status(db, "eng1", "a:b:c", "accepted-risk", reason="client approved")
            disposition = get_status(db, "eng1", "a:b:c")
            assert disposition is not None
            assert disposition.status == "accepted-risk"
            assert disposition.reason == "client approved"

    def test_invalid_status_raises(self):
        from redteam_toolkit.core.status import set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            with pytest.raises(ValueError, match="Invalid status"):
                set_status(db, "eng1", "a:b:c", "not-a-real-status")

    def test_invalid_until_date_raises_eagerly(self):
        """Fails fast at set_status() time with a clear message, rather
        than storing an unparseable string that only breaks later,
        silently, inside is_expired()'s own date.fromisoformat() call."""
        from redteam_toolkit.core.status import set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            with pytest.raises(ValueError):
                set_status(db, "eng1", "a:b:c", "accepted-risk", until="not-a-date")

    def test_setting_again_overwrites_previous_disposition(self):
        from redteam_toolkit.core.status import get_status, set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            set_status(db, "eng1", "a:b:c", "accepted-risk", reason="first")
            set_status(db, "eng1", "a:b:c", "remediated", reason="second")
            disposition = get_status(db, "eng1", "a:b:c")
            assert disposition.status == "remediated"
            assert disposition.reason == "second"

    def test_reverting_to_open_is_a_normal_set_status_call(self):
        from redteam_toolkit.core.status import get_status, set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            set_status(db, "eng1", "a:b:c", "accepted-risk")
            set_status(db, "eng1", "a:b:c", "open")
            disposition = get_status(db, "eng1", "a:b:c")
            assert disposition.status == "open"

    def test_different_engagements_have_independent_dispositions(self):
        """The same finding_key under two different engagement_ids must
        not share a disposition -- confirms the primary key is truly
        (engagement_id, finding_key), not finding_key alone."""
        from redteam_toolkit.core.status import get_status, set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            register_engagement(db, "eng2", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            set_status(db, "eng1", "a:b:c", "accepted-risk")
            assert get_status(db, "eng2", "a:b:c") is None


class TestExpiry:
    def test_past_until_date_reverts_to_open_on_read(self):
        from redteam_toolkit.core.status import get_status, set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            set_status(db, "eng1", "a:b:c", "accepted-risk", until="2020-01-01")
            assert get_status(db, "eng1", "a:b:c") is None

    def test_future_until_date_stays_active(self):
        from redteam_toolkit.core.status import get_status, set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            set_status(db, "eng1", "a:b:c", "accepted-risk", until="2099-01-01")
            disposition = get_status(db, "eng1", "a:b:c")
            assert disposition is not None
            assert disposition.status == "accepted-risk"

    def test_no_until_never_expires(self):
        from redteam_toolkit.core.status import get_status, set_status
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            set_status(db, "eng1", "a:b:c", "accepted-risk")
            assert get_status(db, "eng1", "a:b:c") is not None


class TestFindFindingById:
    def test_finds_a_real_finding_by_its_db_id(self):
        from redteam_toolkit.core.status import find_finding_by_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            save_module_result(db, "eng1", "x", _result("sqli_detection", [_finding("sqli_detection", "Possible SQLi")]))

            import sqlite3
            conn = sqlite3.connect(db)
            finding_id = conn.execute("SELECT id FROM findings").fetchone()[0]
            conn.close()

            row = find_finding_by_id(db, finding_id)
            assert row is not None
            assert row["title"] == "Possible SQLi"
            assert row["engagement_id"] == "eng1"

    def test_returns_none_for_unknown_id(self):
        from redteam_toolkit.core.status import find_finding_by_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            assert find_finding_by_id(db, 99999) is None


class TestAnnotateWithStatus:
    def test_defaults_to_open_when_no_disposition_set(self):
        from redteam_toolkit.core.status import annotate_with_status
        rows = [{"module": "a", "title": "Some Finding", "target": "x"}]
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            annotate_with_status(rows, db, "eng1")
            assert rows[0]["status"] == "open"
            assert "status_reason" not in rows[0]

    def test_annotates_with_the_real_disposition_and_reason(self):
        from redteam_toolkit.core.diff import row_key
        from redteam_toolkit.core.status import annotate_with_status, set_status
        rows = [{"module": "a", "title": "Some Finding", "target": "x"}]
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            set_status(db, "eng1", row_key(rows[0]), "false-positive", reason="not exploitable")
            annotate_with_status(rows, db, "eng1")
            assert rows[0]["status"] == "false-positive"
            assert rows[0]["status_reason"] == "not exploitable"


class TestDiffRegressionExcludesDispositionedFindings:
    """The key integration point between diff.py and status.py: a new
    finding marked false-positive/accepted-risk must not count toward
    has_new_regression, even though it's CRITICAL/HIGH severity."""

    def test_backward_compatible_default_when_status_never_set(self):
        """A DiffResult built without ever calling annotate_with_status()
        (every pre-existing test in test_diff.py does exactly this) must
        keep behaving exactly as before -- 'open' (the .get() default)
        excludes nothing."""
        from redteam_toolkit.core.diff import DiffResult
        result = DiffResult(engagement_id="e", run1_id=1, run2_id=2)
        result.new = [{"severity": "CRITICAL", "module": "a", "title": "t"}]
        assert result.has_new_regression is True

    def test_false_positive_excludes_from_regression(self):
        from redteam_toolkit.core.diff import DiffResult
        result = DiffResult(engagement_id="e", run1_id=1, run2_id=2)
        result.new = [{"severity": "CRITICAL", "module": "a", "title": "t", "status": "false-positive"}]
        assert result.has_new_regression is False

    def test_accepted_risk_excludes_from_regression(self):
        from redteam_toolkit.core.diff import DiffResult
        result = DiffResult(engagement_id="e", run1_id=1, run2_id=2)
        result.new = [{"severity": "HIGH", "module": "a", "title": "t", "status": "accepted-risk"}]
        assert result.has_new_regression is False

    def test_remediated_status_does_not_exclude_a_new_finding(self):
        """'remediated' describes a finding that WAS fixed -- it would
        be a contradiction for a brand-new finding to already be marked
        remediated, but this confirms the exclusion list is specifically
        (false-positive, accepted-risk), not "anything non-open"."""
        from redteam_toolkit.core.diff import DiffResult
        result = DiffResult(engagement_id="e", run1_id=1, run2_id=2)
        result.new = [{"severity": "CRITICAL", "module": "a", "title": "t", "status": "remediated"}]
        assert result.has_new_regression is True

    def test_mixed_new_findings_one_dispositioned_one_not(self):
        from redteam_toolkit.core.diff import DiffResult
        result = DiffResult(engagement_id="e", run1_id=1, run2_id=2)
        result.new = [
            {"severity": "CRITICAL", "module": "a", "title": "dispositioned", "status": "accepted-risk"},
            {"severity": "HIGH", "module": "b", "title": "still open", "status": "open"},
        ]
        assert result.has_new_regression is True

    def test_end_to_end_real_diff_then_triage_removes_regression(self):
        """The full real path: a real diff shows a regression, a real
        triage disposition is applied, re-running the same diff (with
        annotation) no longer shows a regression."""
        from redteam_toolkit.core.diff import diff_runs, row_key
        from redteam_toolkit.core.status import annotate_with_status, set_status

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("a", []))
            run2 = save_module_result(db, "eng1", "x", _result(
                "xss_detection", [_finding("xss_detection", "Reflected XSS", severity=Severity.CRITICAL)],
            ))

            result = diff_runs(db, "eng1", run1, run2)
            assert result.has_new_regression is True

            key = row_key(result.new[0])
            set_status(db, "eng1", key, "false-positive", reason="sanitized by WAF")

            result2 = diff_runs(db, "eng1", run1, run2)
            annotate_with_status(result2.new, db, "eng1")
            assert result2.has_new_regression is False
            assert result2.new[0]["status"] == "false-positive"
