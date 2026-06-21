"""
Open redirect detection — supplies a controlled, distinctive external-
looking target value to parameters that look like redirect destinations
and checks whether the response redirects there. Never follows the
redirect to the externally-supplied destination.
"""

from __future__ import annotations

import http.client
import urllib.parse
from urllib.parse import urlparse

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.core.rate_limit import RateLimiter
from redteam_toolkit.recon.base import BaseReconModule

DEFAULT_PARAMS = ["url", "next", "redirect", "return", "dest", "continue"]
CANARY_TARGET = "https://redteam-toolkit-canary.invalid/open-redirect-check"
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
RATE_PER_SECOND = 5.0


class OpenRedirectModule(BaseReconModule):
    name = "open_redirect_detection"
    category = "active"

    def __init__(self, engagement, fetch_fn=None, timeout: float = 5.0, rate_per_second: float = RATE_PER_SECOND):
        super().__init__(engagement)
        self.timeout = timeout
        self._fetch = fetch_fn or self._default_fetch
        self.rate_limiter = RateLimiter(rate_per_second, global_budget=engagement.rate_budget)
        self.probe_count = 0

    def scan(self, target: str, params: list[str] | None = None) -> list[Finding]:
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "open_redirect_probe", category=self.category)

        params = params or DEFAULT_PARAMS
        findings = []

        for param in params:
            self.rate_limiter.wait()
            self.probe_count += 1
            status, location = self._fetch(target, param, CANARY_TARGET)
            if status in _REDIRECT_STATUSES and location == CANARY_TARGET:
                findings.append(Finding(
                    module=self.name,
                    title=f"Open redirect via parameter '{param}'",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.ACTIVE,
                    target=target,
                    description=f"Supplying an external URL in '{param}' caused a redirect to it.",
                    remediation="Validate redirect targets against an allow-list of internal paths.",
                    cvss_score=6.1,
                    extra={"parameter": param},
                ))

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="No open redirect detected",
                severity=Severity.INFO,
                category=FindingCategory.ACTIVE,
                target=target,
                description=f"Probed {len(params)} parameter(s) — none redirected externally.",
            ))

        return findings

    def _default_fetch(self, target: str, param: str, payload: str) -> tuple[int, str | None]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        parsed = urlparse(url)
        sep = "&" if parsed.query else "?"
        path = f"{parsed.path or '/'}{sep}{param}={urllib.parse.quote(payload, safe='')}"

        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        conn = conn_cls(parsed.hostname, port, timeout=self.timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "redteam-toolkit/0.1"})
            resp = conn.getresponse()
            return resp.status, resp.getheader("Location")
        except Exception:
            return 0, None
        finally:
            conn.close()
