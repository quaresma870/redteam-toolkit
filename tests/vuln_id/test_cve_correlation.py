from __future__ import annotations


class TestCVECorrelation:
    def test_no_services_produces_info_finding(self, engagement_factory):
        from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = CVECorrelationModule(eng, query_fn=lambda p, v: [])
        result = m.run("127.0.0.1")
        assert result.error is None
        assert len(result.findings) == 1
        assert "No fingerprinted" in result.findings[0].title

    def test_matched_cve_produces_finding_with_cvss(self, engagement_factory):
        from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        def canned(product, version):
            return [{"id": "CVE-2021-12345", "summary": "Test", "cvss": 9.8}]
        m = CVECorrelationModule(eng, query_fn=canned)
        result = m.run("127.0.0.1", services=[{"product": "OpenSSH", "version": "7.2", "port": 22}])

        assert len(result.findings) == 1
        assert result.findings[0].cvss_score == 9.8
        assert result.findings[0].severity.value == "CRITICAL"
        assert "CVE-2021-12345" in result.findings[0].title

    def test_no_matching_cves_produces_info_finding(self, engagement_factory):
        from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = CVECorrelationModule(eng, query_fn=lambda p, v: [])
        result = m.run("127.0.0.1", services=[{"product": "nginx", "version": "1.25.3", "port": 80}])
        assert len(result.findings) == 1
        assert "No known CVEs" in result.findings[0].title

    def test_network_failure_degrades_gracefully(self, engagement_factory):
        from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule

        def failing_query(product, version):
            raise ConnectionError("simulated")

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = CVECorrelationModule(eng, query_fn=failing_query)
        result = m.run("127.0.0.1", services=[{"product": "nginx", "version": "1.0", "port": 80}])
        assert result.error is None  # caught inside scan()
        assert "failed" in result.findings[0].title.lower()

    def test_skips_services_with_missing_fields(self, engagement_factory):
        from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        called = {"count": 0}
        def query(p, v):
            called["count"] += 1
            return []
        m = CVECorrelationModule(eng, query_fn=query)
        m.run("127.0.0.1", services=[{"product": None, "version": "1.0"}, {"product": "x", "version": None}])
        assert called["count"] == 0

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["vuln-id"])
        m = CVECorrelationModule(eng, query_fn=lambda p, v: [])
        result = m.run("203.0.113.5", services=[{"product": "x", "version": "1.0"}])
        assert result.error is not None

    def test_disallowed_category_refused(self, engagement_factory):
        from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule

        eng = engagement_factory(allowed_categories=["recon"])  # vuln-id not authorized
        m = CVECorrelationModule(eng, query_fn=lambda p, v: [])
        result = m.run("127.0.0.1", services=[{"product": "x", "version": "1.0"}])
        assert result.error is not None
        assert "category" in result.error


class TestCVSSToSeverity:
    def test_critical_band(self):
        from redteam_toolkit.core.models import Severity
        from redteam_toolkit.vuln_id.cve_correlation import cvss_to_severity
        assert cvss_to_severity(9.8) == Severity.CRITICAL
        assert cvss_to_severity(9.0) == Severity.CRITICAL

    def test_high_band(self):
        from redteam_toolkit.core.models import Severity
        from redteam_toolkit.vuln_id.cve_correlation import cvss_to_severity
        assert cvss_to_severity(7.5) == Severity.HIGH
        assert cvss_to_severity(8.9) == Severity.HIGH

    def test_medium_band(self):
        from redteam_toolkit.core.models import Severity
        from redteam_toolkit.vuln_id.cve_correlation import cvss_to_severity
        assert cvss_to_severity(5.0) == Severity.MEDIUM

    def test_low_band(self):
        from redteam_toolkit.core.models import Severity
        from redteam_toolkit.vuln_id.cve_correlation import cvss_to_severity
        assert cvss_to_severity(1.0) == Severity.LOW

    def test_none_defaults_to_medium(self):
        from redteam_toolkit.core.models import Severity
        from redteam_toolkit.vuln_id.cve_correlation import cvss_to_severity
        assert cvss_to_severity(None) == Severity.MEDIUM
