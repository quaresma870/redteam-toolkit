"""
Local canary listener for SSRF detection — a small HTTP server that records
which tokens received an inbound callback. Used by SSRFDetectionModule.
Always local-only by default; pointing it at a real, internet-reachable
host is the operator's choice when running a genuine engagement, but CI
and the test suite use the local-only default exclusively — never an
external canary service.
"""

from __future__ import annotations

import http.server
import socketserver
import threading


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class LocalCanaryListener:
    def __init__(self, host: str = "127.0.0.1"):
        self._received: set[str] = set()
        self._lock = threading.Lock()
        self.host = host

        self._server = _ThreadingHTTPServer((host, 0), self._make_handler())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _make_handler(self):
        listener = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                token = self.path.strip("/").rsplit("/", 1)[-1]
                with listener._lock:
                    listener._received.add(token)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args) -> None:  # noqa: D102
                pass

        return Handler

    def generate_url(self, token: str) -> str:
        return f"http://{self.host}:{self.port}/callback/{token}"

    def was_called(self, token: str) -> bool:
        with self._lock:
            return token in self._received

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
