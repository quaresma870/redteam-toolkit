"""
SSRF detection via canary/callback — supplies a unique per-parameter canary
URL to parameters that look like they might trigger a server-side fetch,
and checks for an inbound callback. A received callback confirms the
finding; this module never pivots through a confirmed SSRF to reach
additional internal infrastructure — confirmation is the stopping point.
"""

from __future__ import annotations

import secrets
import time
import urllib.parse
import urllib.request

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.core.rate_limit import RateLimiter
from redteam_toolkit.recon.base import BaseReconModule

DEFAULT_PARAMS = ["url", "webhook", "callback", "image", "avatar", "fetch"]
DEFAULT_WAIT_SECONDS = 2.0
RATE_PER_SECOND = 5.0


class SSRFDetectionModule(BaseReconModule):
    name = "ssrf_detection"
    category = "active"

    def __init__(
        self,
        engagement,
        canary_listener=None,
        fetch_fn=None,
        timeout: float = 5.0,
        wait_seconds: float = DEFAULT_WAIT_SECONDS,
        rate_per_second: float = RATE_PER_SECOND,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        self.wait_seconds = wait_seconds
        self._fetch = fetch_fn or self._default_fetch
        # canary_listener: object exposing .generate_url(token) -> str and
        # .was_called(token) -> bool. See active/canary.py for the local,
        # CI-safe implementation. Never an external canary service in tests.
        self._canary = canary_listener
        self.probe_count = 0
        self.rate_limiter = RateLimiter(rate_per_second, global_budget=engagement.rate_budget)

    def scan(self, target: str, params: list[str] | None = None) -> list[Finding]:
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "ssrf_probe", category=self.category)

        if self._canary is None:
            return [Finding(
                module=self.name,
                title="SSRF check skipped — no canary listener configured",
                severity=Severity.INFO,
                category=FindingCategory.ACTIVE,
                target=target,
                description="Provide a canary_listener (e.g. active.canary.LocalCanaryListener) to run this check.",
            )]

        params = params or DEFAULT_PARAMS
        findings = []

        for param in params:
            token = secrets.token_hex(8)
            canary_url = self._canary.generate_url(token)
            self.rate_limiter.wait()
            self.probe_count += 1
            self._fetch(target, param, canary_url)
            time.sleep(self.wait_seconds)

            if self._canary.was_called(token):
                findings.append(Finding(
                    module=self.name,
                    title=f"SSRF confirmed via parameter '{param}'",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.ACTIVE,
                    target=target,
                    description=f"Supplying a canary URL in '{param}' triggered a server-side fetch back to it.",
                    remediation="Validate/allow-list server-side fetch destinations; block requests to internal/link-local IP ranges.",
                    cvss_score=9.1,
                    extra={"parameter": param},
                ))

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="No SSRF detected",
                severity=Severity.INFO,
                category=FindingCategory.ACTIVE,
                target=target,
                description=f"Probed {len(params)} parameter(s) — no canary callbacks received.",
            ))

        return findings

    def _default_fetch(self, target: str, param: str, payload: str) -> None:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        sep = "&" if "?" in url else "?"
        full_url = f"{url}{sep}{param}={urllib.parse.quote(payload, safe='')}"
        req = urllib.request.Request(full_url, headers={"User-Agent": "redteam-toolkit/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
        except Exception:
            pass
