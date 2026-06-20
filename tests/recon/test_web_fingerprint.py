from __future__ import annotations


class TestWebFingerprint:
    def test_identifies_server_header(self, engagement_factory):
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = engagement_factory()
        fetch = lambda target: ({"Server": "nginx/1.25.3"}, "")  # noqa: E731
        m = WebFingerprintModule(eng, fetch_fn=fetch)
        result = m.run("127.0.0.1")

        assert result.error is None
        assert any("nginx" in f.title for f in result.findings)

    def test_identifies_x_powered_by(self, engagement_factory):
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = engagement_factory()
        fetch = lambda target: ({"X-Powered-By": "PHP/8.2"}, "")  # noqa: E731
        m = WebFingerprintModule(eng, fetch_fn=fetch)
        result = m.run("127.0.0.1")
        assert any("PHP/8.2" in f.title for f in result.findings)

    def test_detects_wordpress_signature(self, engagement_factory):
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = engagement_factory()
        body = '<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>'
        fetch = lambda target: ({}, body)  # noqa: E731
        m = WebFingerprintModule(eng, fetch_fn=fetch)
        result = m.run("127.0.0.1")
        assert any("WordPress" in f.title for f in result.findings)

    def test_no_signatures_no_cms_finding(self, engagement_factory):
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = engagement_factory()
        fetch = lambda target: ({}, "<html>plain page</html>")  # noqa: E731
        m = WebFingerprintModule(eng, fetch_fn=fetch)
        result = m.run("127.0.0.1")
        assert not any("CMS detected" in f.title for f in result.findings)

    def test_fetch_failure_degrades_gracefully(self, engagement_factory):
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = engagement_factory()
        def failing_fetch(target):
            raise ConnectionError("simulated")
        m = WebFingerprintModule(eng, fetch_fn=failing_fetch)
        result = m.run("127.0.0.1")
        assert result.error is None  # caught inside scan()
        assert len(result.findings) == 1

    def test_real_request_against_mock_target(self, engagement_factory, mock_target):
        """End-to-end smoke test against the real local mock server, not a
        stubbed fetch_fn — confirms the default HTTP client actually works."""
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = engagement_factory()
        m = WebFingerprintModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}")
        assert result.error is None

    def test_url_target_with_scheme_and_port_passes_scope_check(self, engagement_factory, mock_target):
        """Regression test: scan() previously passed the full URL (scheme +
        port) straight to the scope gate, which only ever matches bare
        hosts/IPs/domains — a URL-style target was therefore ALWAYS refused
        even when the bare host was correctly in scope. Caught during manual
        validation before this test existed.
        """
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = engagement_factory(targets=["127.0.0.1"])  # bare host, as authorization.yml expects
        m = WebFingerprintModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}")
        assert result.error is None, f"target was incorrectly refused: {result.error}"

    def test_out_of_scope_bare_host_still_refused(self, engagement_factory):
        """The fix must not accidentally make scope checking permissive —
        an actually out-of-scope host must still be refused."""
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = engagement_factory(targets=["10.0.0.0/8"])
        m = WebFingerprintModule(eng, fetch_fn=lambda t: ({}, ""))
        result = m.run("http://203.0.113.5:8080")
        assert result.error is not None
        assert "scope" in result.error
