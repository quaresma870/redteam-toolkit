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
import socketserver
import threading


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded so a request that itself triggers a server-side fetch back
    to this same server (the vulnerable SSRF endpoint, deliberately) doesn't
    deadlock against a single-threaded accept loop."""
    daemon_threads = True


_VALID_SESSION_COOKIE = "session=valid-test-token-abc123"


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
            "/safe/sqli": self._safe_sqli,
            "/vulnerable/sqli": self._vulnerable_sqli,
            "/safe/traversal": self._safe_traversal,
            "/vulnerable/traversal": self._vulnerable_traversal,
            "/safe/ssrf": self._safe_ssrf,
            "/vulnerable/ssrf": self._vulnerable_ssrf,
            "/banner": self._banner,
            "/robots.txt": self._robots,
            "/protected/data": self._protected_data,
        }
        handler = routes.get(self.path.split("?")[0])
        if handler:
            handler()
        else:
            self._not_found()

    # ── Routes ────────────────────────────────────────────────────────────────

    def _protected_data(self) -> None:
        """Requires the exact session cookie below — anything else
        (missing entirely, or present but wrong) is refused the same way,
        so a test can confirm auth actually mattered rather than the
        endpoint just being open regardless."""
        cookie_header = self.headers.get("Cookie", "")
        if _VALID_SESSION_COOKIE in cookie_header:
            self._respond(200, "application/json", b'{"secret": "only visible when authenticated"}')
        else:
            self._respond(401, "text/plain", b"authentication required")


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

    def _safe_sqli(self) -> None:
        """Simulates a parameterised query — never returns a SQL error
        signature regardless of input, including quote characters."""
        import urllib.parse

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        user_id = params.get("id", [""])[0]
        # A real parameterised query just treats this as an opaque string —
        # no value of `id` can ever produce a database error.
        body = f"User lookup for id={user_id!r}: not found".encode()
        self._respond(200, "text/plain", body)

    def _vulnerable_sqli(self) -> None:
        """Simulates naive string concatenation into a SQL query —
        deliberately returns a SQL-error-style message whenever the input
        contains a single quote, the classic error-based SQLi signature."""
        import urllib.parse

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        user_id = params.get("id", [""])[0]
        if "'" in user_id:
            body = (
                b"You have an error in your SQL syntax; check the manual that "
                b"corresponds to your database server version for the right "
                b"syntax to use near '" + user_id.encode() + b"'"
            )
        else:
            body = f"User lookup for id={user_id!r}: not found".encode()
        self._respond(200, "text/plain", body)

    def _safe_traversal(self) -> None:
        """Always serves from a fixed safe directory — any '..' sequence is
        rejected outright, never resolved against the filesystem."""
        import urllib.parse

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        filename = params.get("file", [""])[0]
        if ".." in filename or "%2e%2e" in filename.lower():
            body = b"access denied"
        else:
            body = b"=== mock document content ==="
        self._respond(200, "text/plain", body)

    def _vulnerable_traversal(self) -> None:
        """Simulates naive path concatenation — any traversal sequence
        (plain or URL-encoded) returns a recognisable fake /etc/passwd
        line, confirming traversal without needing a real sensitive file."""
        import urllib.parse

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        filename = params.get("file", [""])[0]
        decoded = urllib.parse.unquote(filename)
        if ".." in decoded:
            body = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        else:
            body = b"=== mock document content ==="
        self._respond(200, "text/plain", body)

    def _safe_ssrf(self) -> None:
        """Never performs a server-side fetch of an arbitrary URL parameter
        — only ever reports that external fetches are disabled."""
        self._respond(200, "text/plain", b"external fetch disabled")

    def _vulnerable_ssrf(self) -> None:
        """Simulates a naive 'fetch this image/webhook URL' feature — makes
        a REAL server-side request to whatever URL is supplied, with no
        validation. This is what lets an SSRF canary actually get hit."""
        import urllib.parse
        import urllib.request

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        target_url = params.get("url", [""])[0]
        if not target_url:
            self._respond(400, "text/plain", b"missing url parameter")
            return
        try:
            req = urllib.request.Request(target_url, headers={"User-Agent": "mock-target-ssrf/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read(1024)
            self._respond(200, "text/plain", b"fetched OK")
        except Exception as exc:
            self._respond(200, "text/plain", f"fetch failed: {exc}".encode())

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
    server = _ThreadingHTTPServer((host, 0), MockTargetHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port
