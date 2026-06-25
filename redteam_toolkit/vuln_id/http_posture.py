"""
HTTP security posture — headers, cookies, and CORS configuration on live
targets. Equivalent checks to a config-based static analysis tool, applied
against an actual running target discovered during recon.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.recon.base import BaseReconModule

# Matches the severity mapping used elsewhere in this portfolio for the
# same checks, for consistency.
SECURITY_HEADERS = {
    "Strict-Transport-Security": Severity.HIGH,
    "Content-Security-Policy": Severity.MEDIUM,
    "X-Frame-Options": Severity.MEDIUM,
    "X-Content-Type-Options": Severity.LOW,
}


class HTTPPostureModule(BaseReconModule):
    name = "http_posture"
    category = "vuln-id"

    def __init__(self, engagement, fetch_fn=None, timeout: float = 5.0):
        super().__init__(engagement)
        self.timeout = timeout
        self._fetch = fetch_fn or self._default_fetch

    def scan(self, target: str) -> list[Finding]:
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "http_posture_check", category=self.category)

        try:
            headers = self._fetch(target)
        except Exception as exc:
            return [Finding(
                module=self.name,
                title="HTTP posture request failed",
                severity=Severity.INFO,
                category=FindingCategory.VULN_ID,
                target=target,
                description=str(exc),
            )]

        findings: list[Finding] = []
        findings.extend(self._check_headers(target, headers))
        findings.extend(self._check_cookies(target, headers))
        cors_finding = self._check_cors(target, headers)
        if cors_finding:
            findings.append(cors_finding)

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="HTTP security posture looks healthy",
                severity=Severity.INFO,
                category=FindingCategory.VULN_ID,
                target=target,
                description="All checked headers and cookie flags are present; CORS looks safe.",
            ))

        return findings

    def _check_headers(self, target: str, headers: dict) -> list[Finding]:
        findings = []
        for name, severity in SECURITY_HEADERS.items():
            if name not in headers:
                findings.append(Finding(
                    module=self.name,
                    title=f"Missing header: {name}",
                    severity=severity,
                    category=FindingCategory.VULN_ID,
                    target=target,
                    description=f"Response does not set the {name} header.",
                    remediation=f"Add the {name} response header.",
                ))
        return findings

    def _check_cookies(self, target: str, headers: dict) -> list[Finding]:
        set_cookie = headers.get("Set-Cookie", "")
        if not set_cookie:
            return []

        findings = []
        cookie_lower = set_cookie.lower()
        for flag in ("Secure", "HttpOnly"):
            if flag.lower() not in cookie_lower:
                findings.append(Finding(
                    module=self.name,
                    title=f"Cookie missing {flag} flag",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.VULN_ID,
                    target=target,
                    description=f"Set-Cookie header is missing the {flag} attribute.",
                    evidence=set_cookie[:200],
                ))
        if "samesite" not in cookie_lower:
            findings.append(Finding(
                module=self.name,
                title="Cookie missing SameSite attribute",
                severity=Severity.LOW,
                category=FindingCategory.VULN_ID,
                target=target,
                description="Set-Cookie header does not specify SameSite.",
                evidence=set_cookie[:200],
            ))
        return findings

    def _check_cors(self, target: str, headers: dict) -> Finding | None:
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            return Finding(
                module=self.name,
                title="CORS: wildcard origin with credentials",
                severity=Severity.CRITICAL,
                category=FindingCategory.VULN_ID,
                target=target,
                description="Access-Control-Allow-Origin: * combined with Allow-Credentials: true "
                            "lets any site make authenticated cross-origin requests.",
                remediation="Use an explicit origin allow-list instead of a wildcard.",
                cvss_score=8.1,
            )
        if acao == "*":
            return Finding(
                module=self.name,
                title="CORS: wildcard origin allowed",
                severity=Severity.LOW,
                category=FindingCategory.VULN_ID,
                target=target,
                description="Access-Control-Allow-Origin is '*' — fine for a fully public API, "
                            "worth confirming that's intentional.",
            )
        return None

    def _default_fetch(self, target: str) -> dict:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        headers = {"User-Agent": "redteam-toolkit/0.1"}
        headers.update(self.engagement.auth_headers())
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return dict(exc.headers) if exc.headers else {}
