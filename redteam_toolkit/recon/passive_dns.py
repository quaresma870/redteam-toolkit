"""
Passive DNS enumeration — discovers subdomains via public Certificate
Transparency logs (crt.sh), without sending a single packet to the target
itself. The lowest-risk recon technique available.
"""

from __future__ import annotations

import json
import urllib.request

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.recon.base import BaseReconModule

_CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


class PassiveDNSModule(BaseReconModule):
    name = "passive_dns"

    def __init__(self, engagement, fetch_fn=None, timeout: float = 10.0):
        super().__init__(engagement)
        self.timeout = timeout
        # Injectable so tests supply a canned crt.sh-style response instead
        # of making a real external HTTP call.
        self._fetch = fetch_fn or self._default_fetch

    def scan(self, target: str) -> list[Finding]:
        self.engagement.authorize_action(self.name, target, "ct_log_query", category=self.category)

        try:
            raw = self._fetch(target)
            entries = json.loads(raw) if raw else []
        except Exception:
            return [Finding(
                module=self.name,
                title="Certificate transparency lookup failed",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description="Could not query the CT log source — informational only, not a finding about the target.",
            )]

        subdomains: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "") if isinstance(entry, dict) else ""
            for line in name_value.splitlines():
                line = line.strip().lstrip("*.")
                if line:
                    subdomains.add(line)

        return [
            Finding(
                module=self.name,
                title=f"Subdomain discovered: {sub}",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description="Found via certificate transparency log — no direct contact with the target.",
                extra={"source": "crt.sh", "subdomain": sub},
            )
            for sub in sorted(subdomains)
        ]

    def _default_fetch(self, domain: str) -> str:
        url = _CRTSH_URL.format(domain=domain)
        req = urllib.request.Request(url, headers={"User-Agent": "redteam-toolkit/0.1"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
