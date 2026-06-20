from __future__ import annotations


class TestHTTPPostureHeaders:
    def test_all_headers_missing_flagged(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = HTTPPostureModule(eng, fetch_fn=lambda t: {})
        result = m.run("127.0.0.1")
        titles = [f.title for f in result.findings]
        assert "Missing header: Strict-Transport-Security" in titles
        assert "Missing header: Content-Security-Policy" in titles

    def test_hsts_present_not_flagged(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = HTTPPostureModule(eng, fetch_fn=lambda t: {"Strict-Transport-Security": "max-age=31536000"})
        result = m.run("127.0.0.1")
        assert not any("Strict-Transport-Security" in f.title for f in result.findings)

    def test_all_headers_present_no_header_findings(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {
            "Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        }
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        assert not any("Missing header" in f.title for f in result.findings)


class TestHTTPPostureCookies:
    def test_missing_secure_flag(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {"Set-Cookie": "session=abc123; HttpOnly"}
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        assert any("Secure" in f.title for f in result.findings)

    def test_missing_httponly_flag(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {"Set-Cookie": "session=abc123; Secure"}
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        assert any("HttpOnly" in f.title for f in result.findings)

    def test_missing_samesite(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {"Set-Cookie": "session=abc123; Secure; HttpOnly"}
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        assert any("SameSite" in f.title for f in result.findings)

    def test_fully_flagged_cookie_no_findings(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"}
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        assert not any("Cookie" in f.title for f in result.findings)

    def test_no_cookie_no_cookie_findings(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = HTTPPostureModule(eng, fetch_fn=lambda t: {})
        result = m.run("127.0.0.1")
        assert not any("Cookie" in f.title for f in result.findings)


class TestHTTPPostureCORS:
    def test_wildcard_with_credentials_is_critical(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        cors = next(f for f in result.findings if "CORS" in f.title)
        assert cors.severity.value == "CRITICAL"
        assert cors.cvss_score == 8.1

    def test_wildcard_without_credentials_is_low(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {"Access-Control-Allow-Origin": "*"}
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        cors = next(f for f in result.findings if "CORS" in f.title)
        assert cors.severity.value == "LOW"

    def test_explicit_origin_no_cors_finding(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {"Access-Control-Allow-Origin": "https://trusted.example.com"}
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        assert not any("CORS" in f.title for f in result.findings)


class TestHTTPPostureGeneral:
    def test_fetch_failure_degrades_gracefully(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        def failing_fetch(t):
            raise ConnectionError("simulated")

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = HTTPPostureModule(eng, fetch_fn=failing_fetch)
        result = m.run("127.0.0.1")
        assert result.error is None
        assert len(result.findings) == 1

    def test_perfectly_healthy_response_single_info_finding(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        headers = {
            "Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        }
        m = HTTPPostureModule(eng, fetch_fn=lambda t: headers)
        result = m.run("127.0.0.1")
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"

    def test_real_request_against_mock_target(self, engagement_factory, mock_target):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(targets=["127.0.0.1"], allowed_categories=["vuln-id"])
        m = HTTPPostureModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}")
        assert result.error is None
        # the mock target sets none of the security headers — all flagged
        assert len(result.findings) >= 4

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["vuln-id"])
        m = HTTPPostureModule(eng, fetch_fn=lambda t: {})
        result = m.run("http://203.0.113.5")
        assert result.error is not None
        assert "scope" in result.error
