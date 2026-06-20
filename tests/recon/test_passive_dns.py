from __future__ import annotations

import json


class TestPassiveDNS:
    _CANNED_RESPONSE = json.dumps([
        {"name_value": "www.example.com\nstaging.example.com"},
        {"name_value": "*.dev.example.com"},
        {"name_value": "www.example.com"},  # duplicate, should be deduplicated
    ])

    def test_parses_subdomains_from_canned_response(self, engagement_factory):
        from redteam_toolkit.recon.passive_dns import PassiveDNSModule

        eng = engagement_factory()
        m = PassiveDNSModule(eng, fetch_fn=lambda domain: self._CANNED_RESPONSE)
        result = m.run("example.com")

        assert result.error is None
        subdomains = {f.extra["subdomain"] for f in result.findings}
        assert subdomains == {"www.example.com", "staging.example.com", "dev.example.com"}

    def test_no_real_network_call_made(self, engagement_factory):
        """Confirms the fetch function is the only thing touched — no real
        urllib call happens when fetch_fn is supplied."""
        from redteam_toolkit.recon.passive_dns import PassiveDNSModule

        called = {"count": 0}
        def fake_fetch(domain):
            called["count"] += 1
            return "[]"

        eng = engagement_factory()
        m = PassiveDNSModule(eng, fetch_fn=fake_fetch)
        m.run("example.com")
        assert called["count"] == 1

    def test_fetch_failure_degrades_gracefully(self, engagement_factory):
        from redteam_toolkit.recon.passive_dns import PassiveDNSModule

        eng = engagement_factory()
        def failing_fetch(domain):
            raise ConnectionError("simulated network failure")

        m = PassiveDNSModule(eng, fetch_fn=failing_fetch)
        result = m.run("example.com")
        assert result.error is None  # caught inside scan(), not propagated as a module error
        assert len(result.findings) == 1
        assert "failed" in result.findings[0].title.lower()

    def test_empty_response_produces_no_findings(self, engagement_factory):
        from redteam_toolkit.recon.passive_dns import PassiveDNSModule

        eng = engagement_factory()
        m = PassiveDNSModule(eng, fetch_fn=lambda domain: "[]")
        result = m.run("example.com")
        assert result.findings == []

    def test_action_logged_as_passive_category(self, engagement_factory):
        from redteam_toolkit.recon.passive_dns import PassiveDNSModule

        eng = engagement_factory()
        m = PassiveDNSModule(eng, fetch_fn=lambda domain: "[]")
        m.run("example.com")
        entries = eng.audit_log.read_all()
        assert entries[-1]["detail"]["category"] == "recon"
        assert entries[-1]["action"] == "ct_log_query"

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.recon.passive_dns import PassiveDNSModule

        eng = engagement_factory(targets=["*.example.com"])
        m = PassiveDNSModule(eng, fetch_fn=lambda domain: "[]")
        result = m.run("evil.com")
        assert result.error is not None
