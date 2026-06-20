"""
Web technology fingerprinting — a single GET request, then header analysis
and lightweight CMS signature matching. Deliberately not a crawler — that's
the endpoint_discovery module.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.recon.base import BaseReconModule

_CMS_SIGNATURES: dict[str, list[str]] = {
    "WordPress": ["wp-content", "wp-includes"],
    "Drupal": ["sites/default", "drupal.js", "drupal.settings"],
    "Joomla": ["media/jui", "/joomla"],
}


class WebFingerprintModule(BaseReconModule):
    name = "web_fingerprint"

    def __init__(self, engagement, fetch_fn=None, timeout: float = 5.0):
        super().__init__(engagement)
        self.timeout = timeout
        self._fetch = fetch_fn or self._default_fetch

    def scan(self, target: str) -> list[Finding]:
        self.engagement.authorize_action(
            self.name, extract_host(target), "http_fingerprint", category=self.category,
        )

        try:
            headers, body = self._fetch(target)
        except Exception as exc:
            return [Finding(
                module=self.name,
                title="HTTP fingerprint request failed",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description=str(exc),
            )]

        findings = []

        server = headers.get("Server", "")
        if server:
            findings.append(Finding(
                module=self.name,
                title=f"Web server: {server}",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description="Identified via the Server response header.",
                extra={"server_header": server},
            ))

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            findings.append(Finding(
                module=self.name,
                title=f"X-Powered-By: {powered_by}",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description="Backend technology disclosed via the X-Powered-By header.",
            ))

        body_lower = body.lower()
        for cms, signatures in _CMS_SIGNATURES.items():
            if any(sig in body_lower for sig in signatures):
                findings.append(Finding(
                    module=self.name,
                    title=f"CMS detected: {cms}",
                    severity=Severity.INFO,
                    category=FindingCategory.RECON,
                    target=target,
                    description=f"Page content matches known {cms} static asset paths.",
                ))

        return findings

    def _default_fetch(self, target: str) -> tuple[dict, str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        req = urllib.request.Request(url, headers={"User-Agent": "redteam-toolkit/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = dict(resp.headers)
                body = resp.read().decode("utf-8", errors="replace")
            return headers, body
        except urllib.error.HTTPError as exc:
            headers = dict(exc.headers) if exc.headers else {}
            return headers, ""
