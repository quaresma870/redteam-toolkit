from __future__ import annotations


class TestFingerprintIdentification:
    """Unit tests for the banner-matching logic directly — crafted byte
    strings, not live fake services (out of scope to stand those up)."""

    def _module(self, engagement_factory):
        from redteam_toolkit.recon.fingerprint import FingerprintModule
        return FingerprintModule(engagement_factory())

    def test_identifies_openssh(self, engagement_factory):
        m = self._module(engagement_factory)
        product, version = m._identify(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
        assert product == "OpenSSH"
        assert version == "8.9p1"

    def test_identifies_nginx(self, engagement_factory):
        m = self._module(engagement_factory)
        product, version = m._identify(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n")
        assert product == "nginx"
        assert version == "1.25.3"

    def test_identifies_apache(self, engagement_factory):
        m = self._module(engagement_factory)
        product, version = m._identify(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n")
        assert product == "Apache"
        assert version == "2.4.58"

    def test_identifies_proftpd(self, engagement_factory):
        m = self._module(engagement_factory)
        product, version = m._identify(b"220 ProFTPD 1.3.8 Server ready.\r\n")
        assert product == "ProFTPD"

    def test_identifies_vsftpd(self, engagement_factory):
        m = self._module(engagement_factory)
        product, version = m._identify(b"220 (vsFTPd 3.0.5)\r\n")
        assert product == "vsFTPd"

    def test_identifies_postfix(self, engagement_factory):
        m = self._module(engagement_factory)
        product, version = m._identify(b"220 mail.example.com ESMTP Postfix\r\n")
        assert product == "Postfix"

    def test_unknown_banner_falls_back_gracefully(self, engagement_factory):
        """Never guesses — reports unidentified rather than a wrong product."""
        m = self._module(engagement_factory)
        product, version = m._identify(b"some completely unrecognised banner text")
        assert product is None
        assert version is None


class TestFingerprintScan:
    def test_grabs_banner_and_reports_unknown_when_unmatched(self, engagement_factory):
        from redteam_toolkit.recon.fingerprint import FingerprintModule

        eng = engagement_factory()
        m = FingerprintModule(eng, connect_fn=lambda h, p: b"totally unrecognised service banner")
        result = m.run("127.0.0.1", ports=[9999])
        assert result.error is None
        assert len(result.findings) == 1
        assert "unknown" in result.findings[0].title.lower()

    def test_no_response_produces_no_finding(self, engagement_factory):
        from redteam_toolkit.recon.fingerprint import FingerprintModule

        eng = engagement_factory()
        m = FingerprintModule(eng, connect_fn=lambda h, p: None)
        result = m.run("127.0.0.1", ports=[9999])
        assert result.findings == []

    def test_identified_service_in_title(self, engagement_factory):
        from redteam_toolkit.recon.fingerprint import FingerprintModule

        eng = engagement_factory()
        m = FingerprintModule(eng, connect_fn=lambda h, p: b"SSH-2.0-OpenSSH_9.0\r\n")
        result = m.run("127.0.0.1", ports=[22])
        assert "OpenSSH" in result.findings[0].title

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.recon.fingerprint import FingerprintModule

        eng = engagement_factory(targets=["10.0.0.0/8"])
        m = FingerprintModule(eng, connect_fn=lambda h, p: b"banner")
        result = m.run("203.0.113.5", ports=[22])
        assert result.error is not None
