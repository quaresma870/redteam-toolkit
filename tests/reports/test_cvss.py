from __future__ import annotations

from redteam_toolkit.core.models import Finding, FindingCategory, Severity


class TestEnsureCvssScore:
    def test_assigns_score_when_missing(self):
        from redteam_toolkit.core.cvss import ensure_cvss_score

        f = Finding(module="x", title="t", severity=Severity.HIGH, category=FindingCategory.RECON, target="h")
        assert f.cvss_score is None
        ensure_cvss_score(f)
        assert f.cvss_score == 7.5

    def test_does_not_overwrite_existing_score(self):
        from redteam_toolkit.core.cvss import ensure_cvss_score

        f = Finding(module="x", title="t", severity=Severity.HIGH, category=FindingCategory.RECON,
                   target="h", cvss_score=9.8)
        ensure_cvss_score(f)
        assert f.cvss_score == 9.8

    def test_every_severity_band_covered(self):
        from redteam_toolkit.core.cvss import ensure_cvss_score

        for severity in Severity:
            f = Finding(module="x", title="t", severity=severity, category=FindingCategory.RECON, target="h")
            ensure_cvss_score(f)
            assert f.cvss_score is not None

    def test_descending_order_by_severity(self):
        from redteam_toolkit.core.cvss import INTERNAL_RUBRIC

        assert INTERNAL_RUBRIC[Severity.CRITICAL] > INTERNAL_RUBRIC[Severity.HIGH]
        assert INTERNAL_RUBRIC[Severity.HIGH] > INTERNAL_RUBRIC[Severity.MEDIUM]
        assert INTERNAL_RUBRIC[Severity.MEDIUM] > INTERNAL_RUBRIC[Severity.LOW]
        assert INTERNAL_RUBRIC[Severity.LOW] > INTERNAL_RUBRIC[Severity.INFO]


class TestEnsureAllScored:
    def test_scores_every_finding_in_list(self):
        from redteam_toolkit.core.cvss import ensure_all_scored

        findings = [
            Finding(module="x", title="a", severity=Severity.CRITICAL, category=FindingCategory.ACTIVE, target="h"),
            Finding(module="x", title="b", severity=Severity.LOW, category=FindingCategory.RECON, target="h"),
        ]
        ensure_all_scored(findings)
        assert all(f.cvss_score is not None for f in findings)

    def test_empty_list(self):
        from redteam_toolkit.core.cvss import ensure_all_scored

        assert ensure_all_scored([]) == []


class TestBackwardCompatibleReexport:
    """vuln_id/aggregate.py used to own this logic before Sprint 4
    generalised it project-wide — confirms existing imports still work."""

    def test_vuln_id_aggregate_reexports_same_function(self):
        from redteam_toolkit.core.cvss import ensure_cvss_score as core_fn
        from redteam_toolkit.vuln_id.aggregate import ensure_cvss_score as reexported_fn

        assert core_fn is reexported_fn

    def test_vuln_id_aggregate_reexports_same_rubric(self):
        from redteam_toolkit.core.cvss import INTERNAL_RUBRIC as core_rubric
        from redteam_toolkit.vuln_id.aggregate import INTERNAL_RUBRIC as reexported_rubric

        assert core_rubric is reexported_rubric
