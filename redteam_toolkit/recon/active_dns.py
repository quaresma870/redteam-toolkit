"""
Active DNS enumeration — wordlist-based subdomain brute force (rate-limited)
and a zone transfer (AXFR) misconfiguration check.

The AXFR check is read-only: it confirms whether a nameserver improperly
allows a full zone transfer to anyone who asks. It never alters the zone.
"""

from __future__ import annotations

import socket

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.rate_limit import RateLimiter
from redteam_toolkit.recon.base import BaseReconModule

DEFAULT_WORDLIST = ["www", "mail", "ftp", "api", "staging", "dev", "test", "vpn", "admin", "portal"]
SAFE_RATE_PER_SECOND = 20.0
AGGRESSIVE_RATE_PER_SECOND = 80.0


class ActiveDNSModule(BaseReconModule):
    name = "active_dns"

    def __init__(self, engagement, rate_per_second: float = SAFE_RATE_PER_SECOND, resolve_fn=None):
        super().__init__(engagement)
        self.rate_limiter = RateLimiter(rate_per_second)
        self._resolve = resolve_fn or self._default_resolve

    def scan(self, target: str, wordlist: list[str] | None = None) -> list[Finding]:
        self.engagement.authorize_action(self.name, target, "dns_bruteforce", category=self.category)

        findings = []
        for word in wordlist or DEFAULT_WORDLIST:
            self.rate_limiter.wait()
            candidate = f"{word}.{target}"
            ip = self._resolve(candidate)
            if ip:
                findings.append(Finding(
                    module=self.name,
                    title=f"Subdomain resolved: {candidate}",
                    severity=Severity.INFO,
                    category=FindingCategory.RECON,
                    target=target,
                    description=f"{candidate} resolves to {ip}.",
                    extra={"subdomain": candidate, "ip": ip},
                ))
        return findings

    def _default_resolve(self, hostname: str) -> str | None:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None


class ZoneTransferModule(BaseReconModule):
    name = "zone_transfer"

    def __init__(self, engagement, nameserver_fn=None, axfr_fn=None, timeout: float = 5.0):
        super().__init__(engagement)
        self.timeout = timeout
        self._lookup_nameservers = nameserver_fn or self._default_lookup_nameservers
        self._axfr = axfr_fn or self._default_axfr

    def scan(self, target: str, nameservers: list[str] | None = None) -> list[Finding]:
        self.engagement.authorize_action(self.name, target, "zone_transfer_check", category=self.category)

        nameservers = nameservers if nameservers is not None else self._lookup_nameservers(target)
        if not nameservers:
            return [Finding(
                module=self.name,
                title="No nameservers found",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description="Could not determine authoritative nameservers — zone transfer check skipped.",
            )]

        findings = []
        for ns in nameservers:
            allowed, record_count = self._axfr(target, ns)
            if allowed:
                findings.append(Finding(
                    module=self.name,
                    title=f"Zone transfer ALLOWED on {ns}",
                    severity=Severity.HIGH,
                    category=FindingCategory.RECON,
                    target=target,
                    description=(
                        f"Nameserver {ns} permitted a full AXFR zone transfer for {target}, "
                        f"exposing {record_count} record(s) — potentially every subdomain "
                        f"and internal hostname in the zone."
                    ),
                    remediation="Restrict AXFR to known secondary nameservers only.",
                    extra={"nameserver": ns, "record_count": record_count},
                ))
            else:
                findings.append(Finding(
                    module=self.name,
                    title=f"Zone transfer refused on {ns}",
                    severity=Severity.INFO,
                    category=FindingCategory.RECON,
                    target=target,
                    description=f"Nameserver {ns} correctly refused the AXFR request.",
                    extra={"nameserver": ns},
                ))
        return findings

    def _default_lookup_nameservers(self, domain: str) -> list[str]:
        try:
            import dns.resolver
            answer = dns.resolver.resolve(domain, "NS")
            return [str(r.target).rstrip(".") for r in answer]
        except Exception:
            return []

    def _default_axfr(self, domain: str, nameserver: str) -> tuple[bool, int]:
        try:
            import dns.query
            import dns.zone
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=self.timeout))
            return True, len(zone.nodes)
        except Exception:
            return False, 0
