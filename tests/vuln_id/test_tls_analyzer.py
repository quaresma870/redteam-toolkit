from __future__ import annotations

from datetime import UTC, datetime, timedelta


class TestCheckHostnameMatch:
    def test_exact_san_match(self):
        from redteam_toolkit.vuln_id.tls_analyzer import check_hostname_match
        cert = {"san_names": ["example.com"], "common_name": None}
        assert check_hostname_match(cert, "example.com")

    def test_wildcard_san_match(self):
        from redteam_toolkit.vuln_id.tls_analyzer import check_hostname_match
        cert = {"san_names": ["*.example.com"], "common_name": None}
        assert check_hostname_match(cert, "sub.example.com")

    def test_wildcard_does_not_match_bare_domain(self):
        from redteam_toolkit.vuln_id.tls_analyzer import check_hostname_match
        cert = {"san_names": ["*.example.com"], "common_name": None}
        assert not check_hostname_match(cert, "example.com")

    def test_no_match_returns_false(self):
        from redteam_toolkit.vuln_id.tls_analyzer import check_hostname_match
        cert = {"san_names": ["example.com"], "common_name": None}
        assert not check_hostname_match(cert, "evil.com")

    def test_common_name_fallback(self):
        from redteam_toolkit.vuln_id.tls_analyzer import check_hostname_match
        cert = {"san_names": [], "common_name": "example.com"}
        assert check_hostname_match(cert, "example.com")


class TestTLSAnalyzerWithInjectedInfo:
    def test_deprecated_protocol_flagged(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        connect = lambda h, p: {  # noqa: E731
            "protocol": "TLSv1", "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "not_after": None, "hostname_match": True,
        }
        m = TLSAnalyzerModule(eng, connect_fn=connect)
        result = m.run("127.0.0.1")
        assert any("Deprecated protocol" in f.title for f in result.findings)

    def test_modern_protocol_not_flagged(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        connect = lambda h, p: {  # noqa: E731
            "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
            "not_after": None, "hostname_match": True,
        }
        m = TLSAnalyzerModule(eng, connect_fn=connect)
        result = m.run("127.0.0.1")
        assert not any("Deprecated" in f.title for f in result.findings)

    def test_weak_cipher_flagged(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        connect = lambda h, p: {  # noqa: E731
            "protocol": "TLSv1.2", "cipher": "RC4-MD5",
            "not_after": None, "hostname_match": True,
        }
        m = TLSAnalyzerModule(eng, connect_fn=connect)
        result = m.run("127.0.0.1")
        assert any("Weak cipher" in f.title for f in result.findings)

    def test_expired_certificate_flagged(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        expired = datetime.now(UTC) - timedelta(days=10)
        connect = lambda h, p: {  # noqa: E731
            "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
            "not_after": expired, "hostname_match": True,
        }
        m = TLSAnalyzerModule(eng, connect_fn=connect)
        result = m.run("127.0.0.1")
        assert any("expired" in f.title.lower() for f in result.findings)

    def test_valid_certificate_not_flagged(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        future = datetime.now(UTC) + timedelta(days=300)
        connect = lambda h, p: {  # noqa: E731
            "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
            "not_after": future, "hostname_match": True,
        }
        m = TLSAnalyzerModule(eng, connect_fn=connect)
        result = m.run("127.0.0.1")
        assert not any("expired" in f.title.lower() for f in result.findings)

    def test_hostname_mismatch_flagged(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        future = datetime.now(UTC) + timedelta(days=300)
        connect = lambda h, p: {  # noqa: E731
            "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
            "not_after": future, "hostname_match": False,
        }
        m = TLSAnalyzerModule(eng, connect_fn=connect)
        result = m.run("127.0.0.1")
        assert any("mismatch" in f.title.lower() for f in result.findings)

    def test_clean_config_produces_single_info_finding(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        future = datetime.now(UTC) + timedelta(days=300)
        connect = lambda h, p: {  # noqa: E731
            "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
            "not_after": future, "hostname_match": True,
        }
        m = TLSAnalyzerModule(eng, connect_fn=connect)
        result = m.run("127.0.0.1")
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"

    def test_connection_failure_degrades_gracefully(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        def failing_connect(h, p):
            raise ConnectionRefusedError("simulated")

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = TLSAnalyzerModule(eng, connect_fn=failing_connect)
        result = m.run("127.0.0.1")
        assert result.error is None
        assert "failed" in result.findings[0].title.lower()

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["vuln-id"])
        m = TLSAnalyzerModule(eng, connect_fn=lambda h, p: {})
        result = m.run("203.0.113.5")
        assert result.error is not None


class TestTLSAnalyzerRealHandshake:
    """End-to-end tests against a real, freshly generated self-signed
    certificate and a real TLS handshake — not just injected data."""

    def test_valid_certificate_real_handshake(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule
        from tests.fixtures.tls_server import start_tls_server, stop_tls_server

        sock, port, stop_event = start_tls_server(common_name="127.0.0.1", expired=False)
        try:
            eng = engagement_factory(targets=["127.0.0.1"], allowed_categories=["vuln-id"])
            m = TLSAnalyzerModule(eng, port=port)
            result = m.run("127.0.0.1")
            assert result.error is None
            assert not any("expired" in f.title.lower() for f in result.findings)
        finally:
            stop_tls_server(sock, stop_event)

    def test_expired_certificate_real_handshake(self, engagement_factory):
        from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule
        from tests.fixtures.tls_server import start_tls_server, stop_tls_server

        sock, port, stop_event = start_tls_server(common_name="127.0.0.1", expired=True)
        try:
            eng = engagement_factory(targets=["127.0.0.1"], allowed_categories=["vuln-id"])
            m = TLSAnalyzerModule(eng, port=port)
            result = m.run("127.0.0.1")
            assert result.error is None
            assert any("expired" in f.title.lower() for f in result.findings)
            expired_finding = next(f for f in result.findings if "expired" in f.title.lower())
            assert expired_finding.severity.value == "HIGH"
        finally:
            stop_tls_server(sock, stop_event)
