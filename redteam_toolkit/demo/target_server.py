"""
Demo target server — a minimal, deliberately vulnerable local HTTP server
used only by `redteam-toolkit demo`.

Deliberately separate from tests/fixtures/mock_target/server.py (which is
explicitly "FOR CI USE ONLY" per its own docstring, and lives outside the
installed package — packages.find in pyproject.toml only includes
`redteam_toolkit*`, so a real `pip install redteam-toolkit` user has no
access to anything under tests/ at all). This module lives inside the
real package specifically so `redteam-toolkit demo` works identically
whether run from a cloned source checkout or a real pip install —
confirmed by checking pyproject.toml's package config before deciding
where this needed to live, not assumed.

Only two deliberately vulnerable routes, matching the exact same
detectable-signature shape already proven against real detection modules
in the test suite's mock target (error-based SQLi via a literal
"SQL syntax" phrase the sqli_detection module's signature list matches
case-insensitively, and unescaped reflected XSS) — enough to produce a
handful of real, genuine findings without needing to duplicate every
route the test fixture has.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.parse

_INDEX_BODY = b"""<html><body>
<h1>redteam-toolkit demo target</h1>
<p>This is a deliberately vulnerable local server, started only for
<code>redteam-toolkit demo</code>. It is not exposed beyond localhost.</p>
<ul>
<li><a href="/vulnerable/sqli?id=1">/vulnerable/sqli</a></li>
<li><a href="/vulnerable/reflect?q=hello">/vulnerable/reflect</a></li>
</ul>
</body></html>"""


class _DemoTargetHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D102 — suppress default request logging
        pass

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/":
            self._respond(200, "text/html", _INDEX_BODY)
        elif path == "/vulnerable/sqli":
            self._vulnerable_sqli()
        elif path == "/vulnerable/reflect":
            self._vulnerable_reflect()
        else:
            self._respond(404, "text/plain", b"not found")

    def _vulnerable_sqli(self) -> None:
        """Same detectable shape as the test suite's mock target: a
        single quote in the 'id' parameter produces a literal
        "SQL syntax" error-style message, matching sqli_detection's
        signature list (case-insensitive "sql syntax")."""
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
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

    def _vulnerable_reflect(self) -> None:
        """Reflects the 'q' parameter completely unescaped — matches
        xss_detection's marker-reflection check."""
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        value = params.get("q", [""])[0]
        body = f"<html><body>{value}</body></html>".encode()
        self._respond(200, "text/html", body)

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def start_demo_target(host: str = "127.0.0.1") -> tuple[http.server.HTTPServer, int]:
    """Start the demo target on an ephemeral local port. Returns
    (server, port). Caller is responsible for calling server.shutdown()
    when done."""
    server = _ThreadingHTTPServer((host, 0), _DemoTargetHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port
