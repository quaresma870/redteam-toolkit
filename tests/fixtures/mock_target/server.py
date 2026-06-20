"""
⚠️  FOR CI USE ONLY — NEVER RUN OUTSIDE A TEST SESSION, NEVER EXPOSE TO A NETWORK ⚠️

Minimal local HTTP server with deliberately vulnerable AND deliberately safe
endpoints, used so later sprints' recon/vuln-id/active-detection modules can
be tested in CI against a known, reproducible target — never against real
external infrastructure (which would be slow, flaky, and inappropriate to
do from a CI runner with no authorization record).

Starts on an ephemeral local port for the duration of a test and tears down
after. Use via the `mock_target` pytest fixture (see tests/conftest.py once
later sprints add one) or directly:

    server, port = start_mock_target()
    try:
        ...
    finally:
        server.shutdown()
"""

from __future__ import annotations

import http.server
import threading


class MockTargetHandler(http.server.BaseHTTPRequestHandler):
    """Routes deliberately covering both vulnerable and safe variants of
    common test cases, for later sprints' detection modules to exercise."""

    # Suppress default request logging — keep CI output clean.
    def log_message(self, *args) -> None:  # noqa: D102
        pass

    def do_GET(self) -> None:  # noqa: N802
        routes = {
            "/": self._index,
            "/safe/reflect": self._safe_reflect,
            "/vulnerable/reflect": self._vulnerable_reflect,
            "/safe/redirect": self._safe_redirect,
            "/vulnerable/redirect": self._vulnerable_redirect,
            "/banner": self._banner,
            "/robots.txt": self._robots,
        }
        handler = routes.get(self.path.split("?")[0])
        if handler:
            handler()
        else:
            self._not_found()

    # ── Routes ────────────────────────────────────────────────────────────────

    def _index(self) -> None:
        self._respond(200, "text/plain", b"mock-target ok")

    def _safe_reflect(self) -> None:
        """Properly escapes a query parameter — XSS-safe variant."""
        import html
        import urllib.parse

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        value = params.get("q", [""])[0]
        body = f"<html><body>{html.escape(value)}</body></html>".encode()
        self._respond(200, "text/html", body)

    def _vulnerable_reflect(self) -> None:
        """Reflects a query parameter completely unescaped — deliberately
        XSS-vulnerable, for detection-module tests to confirm against."""
        import urllib.parse

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        value = params.get("q", [""])[0]
        body = f"<html><body>{value}</body></html>".encode()
        self._respond(200, "text/html", body)

    def _safe_redirect(self) -> None:
        """Only redirects to a fixed, validated internal path — not open redirect."""
        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def _vulnerable_redirect(self) -> None:
        """Redirects to whatever 'next' parameter is supplied — open redirect."""
        import urllib.parse

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        target = params.get("next", ["/"])[0]
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()

    def _banner(self) -> None:
        """A fake, fixed service banner for fingerprinting-module tests."""
        self._respond(200, "text/plain", b"MockService/1.2.3")

    def _robots(self) -> None:
        self._respond(200, "text/plain", b"User-agent: *\nDisallow: /private\n")

    def _not_found(self) -> None:
        self._respond(404, "text/plain", b"not found")

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_mock_target(host: str = "127.0.0.1") -> tuple[http.server.HTTPServer, int]:
    """Start the mock target on an ephemeral local port. Returns (server, port).
    Caller is responsible for calling server.shutdown() when done."""
    server = http.server.HTTPServer((host, 0), MockTargetHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port
