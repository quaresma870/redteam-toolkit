from __future__ import annotations

from redteam_toolkit.core.netutil import extract_host


class TestExtractHost:
    def test_bare_hostname_unchanged(self):
        assert extract_host("example.com") == "example.com"

    def test_bare_ip_unchanged(self):
        assert extract_host("127.0.0.1") == "127.0.0.1"

    def test_strips_http_scheme_and_port(self):
        assert extract_host("http://127.0.0.1:8080") == "127.0.0.1"

    def test_strips_https_scheme(self):
        assert extract_host("https://example.com") == "example.com"

    def test_strips_https_scheme_with_path(self):
        assert extract_host("https://example.com/some/path") == "example.com"

    def test_host_colon_port_without_scheme(self):
        assert extract_host("example.com:8443") == "example.com"

    def test_ip_colon_port_without_scheme(self):
        assert extract_host("203.0.113.5:443") == "203.0.113.5"

    def test_host_with_non_numeric_suffix_unchanged(self):
        """A colon followed by something that isn't a port number shouldn't
        be misinterpreted as host:port."""
        assert extract_host("not:a:port") == "not:a:port"
