from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from redteam_toolkit.core.history import register_engagement, save_module_result
from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity


def _result(module: str, findings: list[Finding]) -> ModuleResult:
    return ModuleResult(module=module, findings=findings)


def _finding(module: str, title: str, severity=Severity.INFO, target="example.com") -> Finding:
    return Finding(module=module, title=title, severity=severity, category=FindingCategory.RECON, target=target)


class TestResolveRunId:
    def test_numeric_ref_returned_directly(self):
        from redteam_toolkit.core.diff import resolve_run_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            assert resolve_run_id(db, "eng1", "42") == 42

    def test_latest_resolves_to_most_recent_run(self):
        from redteam_toolkit.core.diff import resolve_run_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            save_module_result(db, "eng1", "x", _result("a", [_finding("a", "f1")]))
            run2 = save_module_result(db, "eng1", "x", _result("b", [_finding("b", "f2")]))
            assert resolve_run_id(db, "eng1", "latest") == run2

    def test_previous_resolves_to_second_most_recent(self):
        from redteam_toolkit.core.diff import resolve_run_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("a", [_finding("a", "f1")]))
            save_module_result(db, "eng1", "x", _result("b", [_finding("b", "f2")]))
            assert resolve_run_id(db, "eng1", "previous") == run1

    def test_previous_raises_with_fewer_than_two_runs(self):
        from redteam_toolkit.core.diff import resolve_run_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            save_module_result(db, "eng1", "x", _result("a", [_finding("a", "f1")]))
            with pytest.raises(ValueError, match="Not enough runs"):
                resolve_run_id(db, "eng1", "previous")

    def test_latest_raises_with_no_runs_at_all(self):
        from redteam_toolkit.core.diff import resolve_run_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            with pytest.raises(ValueError, match="No runs found"):
                resolve_run_id(db, "eng1", "latest")

    def test_invalid_ref_raises(self):
        from redteam_toolkit.core.diff import resolve_run_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            with pytest.raises(ValueError, match="Invalid run reference"):
                resolve_run_id(db, "eng1", "yesterday")


class TestDiffRuns:
    """The three acceptance-criteria scenarios from the issue, plus the
    same-module-rerun nuance that an earlier (cumulative-union) version of
    get_findings_as_of got wrong: caught by actually constructing this
    exact scenario and seeing 'resolved' incorrectly stay empty, not
    reasoned through up front."""

    def test_finding_added_between_runs_is_new(self):
        from redteam_toolkit.core.diff import diff_runs
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("a", [_finding("a", "existing finding")]))
            run2 = save_module_result(db, "eng1", "x", _result(
                "a", [_finding("a", "existing finding"), _finding("b", "brand new finding")],
            ))
            result = diff_runs(db, "eng1", run1, run2)
            assert [f["title"] for f in result.new] == ["brand new finding"]

    def test_finding_present_in_both_is_not_new(self):
        from redteam_toolkit.core.diff import diff_runs
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("a", [_finding("a", "same finding")]))
            run2 = save_module_result(db, "eng1", "x", _result("a", [_finding("a", "same finding")]))
            result = diff_runs(db, "eng1", run1, run2)
            assert result.new == []
            assert result.unchanged_count == 1

    def test_finding_absent_in_module_rerun_is_resolved(self):
        """The module is re-run with the finding no longer present —
        correctly reported as resolved, not silently retained from the
        earlier run."""
        from redteam_toolkit.core.diff import diff_runs
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("port_scanner", [_finding("port_scanner", "Open port: 22")]))
            run2 = save_module_result(db, "eng1", "x", _result("port_scanner", []))  # re-run, now clean
            result = diff_runs(db, "eng1", run1, run2)
            assert [f["title"] for f in result.resolved] == ["Open port: 22"]
            assert result.new == []

    def test_finding_from_a_module_never_rerun_stays_unchanged(self):
        """A module that ran once and was never re-run must not have its
        findings disappear from later snapshots just because run2 is a
        later point in time — its most-recent (only) run is still <=
        run2's cutoff."""
        from redteam_toolkit.core.diff import diff_runs
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("passive_dns", [_finding("passive_dns", "subdomain found")]))
            run2 = save_module_result(db, "eng1", "x", _result("port_scanner", [_finding("port_scanner", "Open port: 80")]))
            result = diff_runs(db, "eng1", run1, run2)
            assert result.unchanged_count == 1
            assert [f["title"] for f in result.new] == ["Open port: 80"]

    def test_matching_is_by_stable_key_not_exact_object_identity(self):
        """Same module+title+target across two Finding objects with
        different evidence text must still match as the same logical
        finding (matched by stable key, not exact row equality)."""
        from redteam_toolkit.core.diff import diff_runs
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            f1 = Finding(module="a", title="Same Finding", severity=Severity.INFO,
                         category=FindingCategory.RECON, target="x", evidence="evidence v1")
            f2 = Finding(module="a", title="Same Finding", severity=Severity.INFO,
                         category=FindingCategory.RECON, target="x", evidence="evidence v2 — slightly different")
            run1 = save_module_result(db, "eng1", "x", _result("a", [f1]))
            run2 = save_module_result(db, "eng1", "x", _result("a", [f2]))
            result = diff_runs(db, "eng1", run1, run2)
            assert result.new == []
            assert result.resolved == []
            assert result.unchanged_count == 1

    def test_has_new_regression_true_for_high_severity_new_finding(self):
        from redteam_toolkit.core.diff import diff_runs
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("a", []))
            run2 = save_module_result(db, "eng1", "x", _result(
                "a", [_finding("a", "critical issue", severity=Severity.CRITICAL)],
            ))
            result = diff_runs(db, "eng1", run1, run2)
            assert result.has_new_regression is True

    def test_has_new_regression_false_when_new_findings_are_low_severity(self):
        from redteam_toolkit.core.diff import diff_runs
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("a", []))
            run2 = save_module_result(db, "eng1", "x", _result(
                "a", [_finding("a", "minor note", severity=Severity.INFO)],
            ))
            result = diff_runs(db, "eng1", run1, run2)
            assert result.has_new_regression is False

    def test_to_dict_shape(self):
        from redteam_toolkit.core.diff import diff_runs
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "eng.db")
            register_engagement(db, "eng1", "Acme", "Jane", ["x"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db, "eng1", "x", _result("a", []))
            run2 = save_module_result(db, "eng1", "x", _result("a", [_finding("a", "new one")]))
            result = diff_runs(db, "eng1", run1, run2)
            d_ = result.to_dict()
            assert set(d_.keys()) == {"engagement_id", "run1", "run2", "new", "resolved", "unchanged_count", "regression"}
            assert d_["run1"] == run1
            assert d_["run2"] == run2
