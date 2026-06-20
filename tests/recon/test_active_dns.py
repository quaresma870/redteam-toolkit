from __future__ import annotations

import time


class TestActiveDNS:
    def test_resolves_known_subdomain(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ActiveDNSModule

        eng = engagement_factory(targets=["*.example.com"])
        resolve = lambda host: "203.0.113.10" if host == "www.example.com" else None  # noqa: E731
        m = ActiveDNSModule(eng, rate_per_second=1000, resolve_fn=resolve)
        result = m.run("example.com", wordlist=["www", "nonexistent"])

        assert result.error is None
        assert len(result.findings) == 1
        assert "www.example.com" in result.findings[0].title

    def test_no_matches_produces_no_findings(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ActiveDNSModule

        eng = engagement_factory(targets=["*.example.com"])
        m = ActiveDNSModule(eng, rate_per_second=1000, resolve_fn=lambda host: None)
        result = m.run("example.com", wordlist=["a", "b"])
        assert result.findings == []

    def test_rate_limit_respected(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ActiveDNSModule

        eng = engagement_factory(targets=["*.example.com"])
        rate = 10.0
        m = ActiveDNSModule(eng, rate_per_second=rate, resolve_fn=lambda host: None)
        wordlist = ["w" + str(i) for i in range(8)]

        start = time.monotonic()
        m.run("example.com", wordlist=wordlist)
        elapsed = time.monotonic() - start

        min_expected = (len(wordlist) - 1) / rate
        assert elapsed >= min_expected * 0.8

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ActiveDNSModule

        eng = engagement_factory(targets=["*.example.com"])
        m = ActiveDNSModule(eng, resolve_fn=lambda host: "1.2.3.4")
        result = m.run("evil.com")
        assert result.error is not None


class TestZoneTransfer:
    def test_allowed_transfer_is_high_severity_finding(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ZoneTransferModule

        eng = engagement_factory(targets=["*.example.com"])
        m = ZoneTransferModule(
            eng,
            nameserver_fn=lambda domain: ["ns1.example.com"],
            axfr_fn=lambda domain, ns: (True, 42),
        )
        result = m.run("example.com")

        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "HIGH"
        assert "ALLOWED" in result.findings[0].title
        assert result.findings[0].extra["record_count"] == 42

    def test_refused_transfer_is_info_finding(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ZoneTransferModule

        eng = engagement_factory(targets=["*.example.com"])
        m = ZoneTransferModule(
            eng,
            nameserver_fn=lambda domain: ["ns1.example.com"],
            axfr_fn=lambda domain, ns: (False, 0),
        )
        result = m.run("example.com")

        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"
        assert "refused" in result.findings[0].title.lower()

    def test_multiple_nameservers_each_checked(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ZoneTransferModule

        eng = engagement_factory(targets=["*.example.com"])
        m = ZoneTransferModule(
            eng,
            nameserver_fn=lambda domain: ["ns1.example.com", "ns2.example.com"],
            axfr_fn=lambda domain, ns: (ns == "ns1.example.com", 5),
        )
        result = m.run("example.com")

        assert len(result.findings) == 2
        allowed = [f for f in result.findings if f.severity.value == "HIGH"]
        assert len(allowed) == 1
        assert allowed[0].extra["nameserver"] == "ns1.example.com"

    def test_no_nameservers_found_produces_info_finding(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ZoneTransferModule

        eng = engagement_factory(targets=["*.example.com"])
        m = ZoneTransferModule(eng, nameserver_fn=lambda domain: [])
        result = m.run("example.com")
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.recon.active_dns import ZoneTransferModule

        eng = engagement_factory(targets=["*.example.com"])
        m = ZoneTransferModule(eng, nameserver_fn=lambda d: ["ns1"], axfr_fn=lambda d, ns: (True, 1))
        result = m.run("evil.com")
        assert result.error is not None
