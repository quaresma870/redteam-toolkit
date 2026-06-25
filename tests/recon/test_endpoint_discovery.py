from __future__ import annotations

import time


def _fake_fetch_factory(routes: dict[str, int]):
    """routes: path-suffix -> status code. Anything unmatched returns 404."""
    def fetch(url):
        for suffix, status in routes.items():
            if url.endswith(suffix):
                return status, ""
        return 404, ""
    return fetch


class TestEndpointDiscovery:
    def test_discovers_existing_path(self, engagement_factory):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()
        fetch = _fake_fetch_factory({"/admin": 200})
        m = EndpointDiscoveryModule(eng, fetch_fn=fetch, rate_per_second=1000, respect_robots=False)
        result = m.run("http://127.0.0.1", wordlist=["admin", "nonexistent"])

        assert result.error is None
        assert len(result.findings) == 1
        assert "/admin" in result.findings[0].title

    def test_admin_path_categorised_correctly(self, engagement_factory):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()
        fetch = _fake_fetch_factory({"/admin": 200})
        m = EndpointDiscoveryModule(eng, fetch_fn=fetch, rate_per_second=1000, respect_robots=False)
        result = m.run("http://127.0.0.1", wordlist=["admin"])
        assert result.findings[0].extra["category_hint"] == "admin panel"

    def test_no_existing_paths_no_findings(self, engagement_factory):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()
        fetch = _fake_fetch_factory({})
        m = EndpointDiscoveryModule(eng, fetch_fn=fetch, rate_per_second=1000, respect_robots=False)
        result = m.run("http://127.0.0.1", wordlist=["admin", "login"])
        assert result.findings == []

    def test_robots_disallow_respected_by_default(self, engagement_factory):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()
        def fetch(url):
            if url.endswith("/robots.txt"):
                return 200, "User-agent: *\nDisallow: /admin\n"
            if url.endswith("/admin"):
                return 200, ""  # would be discovered if probed
            return 404, ""
        m = EndpointDiscoveryModule(eng, fetch_fn=fetch, rate_per_second=1000, respect_robots=True)
        result = m.run("http://127.0.0.1", wordlist=["admin"])
        assert result.findings == []  # skipped because robots.txt disallows it

    def test_respect_robots_false_probes_disallowed_paths(self, engagement_factory):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()
        def fetch(url):
            if url.endswith("/robots.txt"):
                return 200, "User-agent: *\nDisallow: /admin\n"
            if url.endswith("/admin"):
                return 200, ""
            return 404, ""
        m = EndpointDiscoveryModule(eng, fetch_fn=fetch, rate_per_second=1000, respect_robots=False)
        result = m.run("http://127.0.0.1", wordlist=["admin"])
        assert len(result.findings) == 1

    def test_sitemap_entries_reported_without_probing(self, engagement_factory):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()
        def fetch(url):
            if url.endswith("/sitemap.xml"):
                return 200, "<urlset><url><loc>http://127.0.0.1/page1</loc></url></urlset>"
            return 404, ""
        m = EndpointDiscoveryModule(eng, fetch_fn=fetch, rate_per_second=1000, respect_robots=False)
        result = m.run("http://127.0.0.1", wordlist=[])
        assert len(result.findings) == 1
        assert "sitemap.xml" in result.findings[0].extra["source"]

    def test_rate_limit_respected(self, engagement_factory):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()
        rate = 10.0
        fetch = _fake_fetch_factory({})
        m = EndpointDiscoveryModule(eng, fetch_fn=fetch, rate_per_second=rate, respect_robots=False)
        wordlist = ["p" + str(i) for i in range(8)]

        start = time.monotonic()
        m.run("http://127.0.0.1", wordlist=wordlist)
        elapsed = time.monotonic() - start
        min_expected = (len(wordlist) - 1) / rate
        assert elapsed >= min_expected * 0.8

    def test_real_request_against_mock_target(self, engagement_factory, mock_target):
        """End-to-end against the real local mock server: 'banner' exists,
        a made-up path doesn't — confirms both directions with the default
        HTTP client, not a stub."""
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()
        m = EndpointDiscoveryModule(eng, rate_per_second=1000, respect_robots=False)
        result = m.run(f"http://127.0.0.1:{mock_target}", wordlist=["banner", "totally-made-up-path"])

        assert result.error is None
        assert len(result.findings) == 1
        assert "banner" in result.findings[0].title

    def test_url_target_with_scheme_and_port_passes_scope_check(self, engagement_factory, mock_target):
        """Same regression class as web_fingerprint: a URL-style target must
        be matched against authorization.yml's bare-host scope entries, not
        refused just because of the scheme/port in the string."""
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory(targets=["127.0.0.1"])
        m = EndpointDiscoveryModule(eng, rate_per_second=1000, respect_robots=False)
        result = m.run(f"http://127.0.0.1:{mock_target}", wordlist=["banner"])
        assert result.error is None, f"target was incorrectly refused: {result.error}"

    def test_out_of_scope_bare_host_still_refused(self, engagement_factory):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory(targets=["10.0.0.0/8"])
        fetch = _fake_fetch_factory({"/admin": 200})
        m = EndpointDiscoveryModule(eng, fetch_fn=fetch, respect_robots=False)
        result = m.run("http://203.0.113.5:8080", wordlist=["admin"])
        assert result.error is not None
        assert "scope" in result.error


class TestAuthenticatedScanning:
    """Issue #39's acceptance criteria, verified end-to-end against the
    real mock-target server's session-cookie-protected /protected/data
    route (tests/fixtures/mock_target/server.py) — not mocked at the
    fetch_fn level, since the whole point is confirming the REAL default
    HTTP fetch implementation actually attaches the configured session
    header to a real outgoing request."""

    def test_authenticated_request_discovers_protected_endpoint(self, engagement_factory, mock_target):
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory(session_auth_headers={"Cookie": "session=valid-test-token-abc123"})
        m = EndpointDiscoveryModule(eng, rate_per_second=1000, respect_robots=False)
        result = m.run(f"http://127.0.0.1:{mock_target}", wordlist=["protected/data"])

        assert result.error is None
        assert len(result.findings) == 1
        assert "protected/data" in result.findings[0].title
        assert "(200)" in result.findings[0].title

    def test_unauthenticated_request_does_not_discover_protected_endpoint(self, engagement_factory, mock_target):
        """Same target, same wordlist, no session_auth configured at all
        — the protected endpoint must NOT be discovered (it 401s, which
        is >= 400 and therefore filtered out), proving authentication
        actually mattered rather than the endpoint just always being
        reachable regardless."""
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory()  # no session_auth_headers at all
        m = EndpointDiscoveryModule(eng, rate_per_second=1000, respect_robots=False)
        result = m.run(f"http://127.0.0.1:{mock_target}", wordlist=["protected/data"])

        assert result.error is None
        assert result.findings == []

    def test_wrong_session_value_also_refused(self, engagement_factory, mock_target):
        """A configured-but-wrong session header behaves the same as no
        header at all — confirms the mock server (and by extension this
        test) is actually checking the credential's value, not just its
        presence."""
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        eng = engagement_factory(session_auth_headers={"Cookie": "session=wrong-token"})
        m = EndpointDiscoveryModule(eng, rate_per_second=1000, respect_robots=False)
        result = m.run(f"http://127.0.0.1:{mock_target}", wordlist=["protected/data"])

        assert result.findings == []

    def test_session_header_value_never_appears_in_finding_or_audit_log(self, engagement_factory, mock_target):
        """Acceptance criterion: session credentials are never written to
        a report or log in plaintext. Checks the actual rendered finding
        AND the actual audit log file content — not just that the
        SessionAuth object's own repr is redacted (already covered
        elsewhere), but that nothing downstream ever serialises the raw
        value into anything persisted."""
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule

        secret_token = "session=valid-test-token-abc123"
        eng = engagement_factory(session_auth_headers={"Cookie": secret_token})
        m = EndpointDiscoveryModule(eng, rate_per_second=1000, respect_robots=False)
        result = m.run(f"http://127.0.0.1:{mock_target}", wordlist=["protected/data"])

        for finding in result.findings:
            assert secret_token not in repr(finding)
            assert secret_token not in str(finding.extra)

        audit_log_content = eng.audit_log.path.read_text()
        assert secret_token not in audit_log_content
