from __future__ import annotations

from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity


class TestEnsureCVSSScore:
    def test_assigns_score_when_missing(self):
        from redteam_toolkit.vuln_id.aggregate import ensure_cvss_score

        f = Finding(module="x", title="t", severity=Severity.HIGH, category=FindingCategory.VULN_ID, target="h")
        assert f.cvss_score is None
        ensure_cvss_score(f)
        assert f.cvss_score == 7.5

    def test_does_not_overwrite_existing_score(self):
        from redteam_toolkit.vuln_id.aggregate import ensure_cvss_score

        f = Finding(module="x", title="t", severity=Severity.HIGH, category=FindingCategory.VULN_ID,
                   target="h", cvss_score=9.8)
        ensure_cvss_score(f)
        assert f.cvss_score == 9.8

    def test_every_severity_band_has_a_score(self):
        from redteam_toolkit.vuln_id.aggregate import ensure_cvss_score

        for severity in Severity:
            f = Finding(module="x", title="t", severity=severity, category=FindingCategory.VULN_ID, target="h")
            ensure_cvss_score(f)
            assert f.cvss_score is not None

    def test_critical_score_higher_than_high(self):
        from redteam_toolkit.vuln_id.aggregate import INTERNAL_RUBRIC
        assert INTERNAL_RUBRIC[Severity.CRITICAL] > INTERNAL_RUBRIC[Severity.HIGH]
        assert INTERNAL_RUBRIC[Severity.HIGH] > INTERNAL_RUBRIC[Severity.MEDIUM]
        assert INTERNAL_RUBRIC[Severity.MEDIUM] > INTERNAL_RUBRIC[Severity.LOW]


class TestAggregate:
    def test_groups_by_target_and_severity(self):
        from redteam_toolkit.vuln_id.aggregate import aggregate

        mr1 = ModuleResult(module="tls_analyzer")
        mr1.findings = [
            Finding(module="tls_analyzer", title="a", severity=Severity.HIGH,
                   category=FindingCategory.VULN_ID, target="host1"),
        ]
        mr2 = ModuleResult(module="cve_correlation")
        mr2.findings = [
            Finding(module="cve_correlation", title="b", severity=Severity.CRITICAL,
                   category=FindingCategory.VULN_ID, target="host1", cvss_score=9.8),
            Finding(module="cve_correlation", title="c", severity=Severity.LOW,
                   category=FindingCategory.VULN_ID, target="host2"),
        ]
        summary = aggregate([mr1, mr2])

        assert summary["total_findings"] == 3
        assert summary["targets"]["host1"]["HIGH"] == 1
        assert summary["targets"]["host1"]["CRITICAL"] == 1
        assert summary["targets"]["host2"]["LOW"] == 1

    def test_every_finding_has_cvss_after_aggregation(self):
        from redteam_toolkit.vuln_id.aggregate import aggregate

        mr = ModuleResult(module="x")
        mr.findings = [
            Finding(module="x", title="a", severity=Severity.MEDIUM, category=FindingCategory.VULN_ID, target="h"),
        ]
        aggregate([mr])
        assert mr.findings[0].cvss_score is not None

    def test_empty_input(self):
        from redteam_toolkit.vuln_id.aggregate import aggregate
        summary = aggregate([])
        assert summary["total_findings"] == 0
        assert summary["targets"] == {}

    def test_module_with_no_findings(self):
        from redteam_toolkit.vuln_id.aggregate import aggregate
        summary = aggregate([ModuleResult(module="x")])
        assert summary["total_findings"] == 0
