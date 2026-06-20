"""
Default credential spot-check — the highest-risk module in this sprint,
built deliberately conservatively:

  - a small, curated list of well-known default credential pairs, never a
    brute-force wordlist
  - exactly ONE attempt per credential pair, then move on — this is a
    spot-check, not an iterative attack
  - a hard rate limit stricter than every other module (this category is
    the most likely to trigger lockouts or alerting on the target side)
  - requires explicit opt-in even when 'vuln-id' is an authorized category —
    being in scope is not the same as being asked to run this specific check

No protocol-specific login client (SSH, MySQL, Redis, etc.) ships with this
module by default — that would mean bundling a meaningful client library per
service. `try_login_fn` is the extension point: callers supply the actual
login attempt logic for whichever services they need checked. Without one
supplied, every attempt is a safe no-op that always reports failure.
"""

from __future__ import annotations

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.core.rate_limit import RateLimiter
from redteam_toolkit.recon.base import BaseReconModule

# Small and curated — NOT a brute-force wordlist. (service_label, username, password)
DEFAULT_CREDENTIALS: list[tuple[str, str, str]] = [
    ("SSH", "root", "root"),
    ("SSH", "admin", "admin"),
    ("MySQL", "root", ""),
    ("PostgreSQL", "postgres", "postgres"),
    ("Redis", "", ""),  # historically no auth by default
    ("MongoDB", "", ""),
    ("Tomcat Manager", "admin", "admin"),
    ("phpMyAdmin", "root", "root"),
]

# Deliberately stricter than other modules' defaults.
SAFE_RATE_PER_SECOND = 1.0


class DefaultCredentialModule(BaseReconModule):
    name = "default_credentials"
    category = "vuln-id"

    def __init__(self, engagement, try_login_fn=None, rate_per_second: float = SAFE_RATE_PER_SECOND):
        super().__init__(engagement)
        self.rate_limiter = RateLimiter(rate_per_second)
        self._try_login = try_login_fn or self._default_try_login
        self.attempt_count = 0  # exposed for tests to assert the request-count ceiling

    def scan(
        self,
        target: str,
        opt_in: bool = False,
        credentials: list[tuple[str, str, str]] | None = None,
    ) -> list[Finding]:
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "default_credential_check", category=self.category)

        if not opt_in:
            return [Finding(
                module=self.name,
                title="Default credential check skipped — not opted in",
                severity=Severity.INFO,
                category=FindingCategory.VULN_ID,
                target=target,
                description="This module requires an explicit opt-in (--check-default-creds) "
                            "even when 'vuln-id' is an authorized category.",
            )]

        findings = []
        for service, username, password in (credentials or DEFAULT_CREDENTIALS):
            self.rate_limiter.wait()
            self.attempt_count += 1
            if self._try_login(host, service, username, password):
                label = f"{username or '<blank>'}/{password or '<blank>'}"
                findings.append(Finding(
                    module=self.name,
                    title=f"Default credentials valid: {service} ({label})",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.VULN_ID,
                    target=target,
                    description=f"{service} accepted the default credential pair {label}.",
                    remediation="Change the default credentials immediately and audit for unauthorized access.",
                    cvss_score=9.8,
                    extra={"service": service},
                ))
            # Exactly one attempt for this pair — always advance to the next,
            # never retry, regardless of the outcome.

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="No default credentials accepted",
                severity=Severity.INFO,
                category=FindingCategory.VULN_ID,
                target=target,
                description=f"Checked {self.attempt_count} default credential pair(s) — none were accepted.",
            ))

        return findings

    def _default_try_login(self, host: str, service: str, username: str, password: str) -> bool:
        return False
