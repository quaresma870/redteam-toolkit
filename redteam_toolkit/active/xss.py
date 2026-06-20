"""
Reflected XSS detection — injects a unique, non-executing marker string per
parameter and checks whether it's reflected unescaped. Detection of
unescaped reflection is sufficient evidence; this module never delivers a
payload that would actually execute in a browser context (no headless
browser, no script execution step).
"""

from __future__ import annotations

import secrets
import urllib.parse
import urllib.request

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.recon.base import BaseReconModule

DEFAULT_PARAMS = ["q"]
MAX_PROBES_PER_PARAM = 1  # one unique marker per parameter is sufficient


class XSSDetectionModule(BaseReconModule):
    name = "xss_detection"
    category = "active"

    def __init__(self, engagement, fetch_fn=None, timeout: float = 5.0):
        super().__init__(engagement)
        self.timeout = timeout
        self._fetch = fetch_fn or self._default_fetch
        self.probe_count = 0

    def scan(self, target: str, params: list[str] | None = None) -> list[Finding]:
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "xss_probe", category=self.category)

        params = params or DEFAULT_PARAMS
        findings = []

        for param in params:
            # A unique marker per request avoids false positives from
            # cached or templated content containing a static test string.
            marker = f"rtk{secrets.token_hex(6)}"
            payload = f"<script>{marker}</script>"
            self.probe_count += 1
            body = self._fetch(target, param, payload)

            if payload in body:
                idx = body.find(payload)
                findings.append(Finding(
                    module=self.name,
                    title=f"Reflected XSS in parameter '{param}'",
                    severity=Severity.HIGH,
                    category=FindingCategory.ACTIVE,
                    target=target,
                    description=f"A marker payload injected into '{param}' was reflected unescaped.",
                    evidence=body[max(0, idx - 20):idx + len(payload) + 10],
                    remediation="Apply contextual output encoding to all reflected user input.",
                    cvss_score=7.4,
                    extra={"parameter": param},
                ))

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="No reflected XSS detected",
                severity=Severity.INFO,
                category=FindingCategory.ACTIVE,
                target=target,
                description=f"Probed {len(params)} parameter(s) — no unescaped reflection observed.",
            ))

        return findings

    def _default_fetch(self, target: str, param: str, payload: str) -> str:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        sep = "&" if "?" in url else "?"
        full_url = f"{url}{sep}{param}={urllib.parse.quote(payload, safe='')}"
        req = urllib.request.Request(full_url, headers={"User-Agent": "redteam-toolkit/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ""
