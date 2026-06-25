"""
Endpoint and directory discovery — checks robots.txt and sitemap.xml
directly first (zero guessing needed for those entries), then probes a
small curated wordlist of common paths. Respects robots.txt Disallow
entries by default (opt-out via respect_robots=False, since an engagement
may legitimately need to check disallowed paths, but the default stays
conservative).
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from urllib.parse import urljoin

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.core.rate_limit import RateLimiter
from redteam_toolkit.recon.base import BaseReconModule

DEFAULT_WORDLIST = [
    "admin", "login", "wp-admin", ".git/HEAD", ".env", "backup.zip",
    "api", ".well-known/security.txt", "config.php.bak",
]

_PATH_CATEGORY_HINTS = (
    ("wp-admin", "admin panel"),
    ("admin", "admin panel"),
    ("login", "admin panel"),
    (".git", "version control exposure"),
    (".env", "configuration exposure"),
    ("backup", "backup file"),
    (".bak", "backup file"),
    ("api", "API endpoint"),
)

SAFE_RATE_PER_SECOND = 10.0
AGGRESSIVE_RATE_PER_SECOND = 40.0


class EndpointDiscoveryModule(BaseReconModule):
    name = "endpoint_discovery"

    def __init__(
        self,
        engagement,
        fetch_fn=None,
        rate_per_second: float = SAFE_RATE_PER_SECOND,
        respect_robots: bool = True,
    ):
        super().__init__(engagement)
        self.rate_limiter = RateLimiter(rate_per_second, global_budget=engagement.rate_budget)
        self.respect_robots = respect_robots
        self._fetch = fetch_fn or self._default_fetch

    def scan(self, target: str, wordlist: list[str] | None = None) -> list[Finding]:
        self.engagement.authorize_action(
            self.name, extract_host(target), "endpoint_discovery", category=self.category,
        )

        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        findings: list[Finding] = []

        findings.extend(self._check_sitemap(base_url, target))

        disallowed = self._parse_robots(base_url)
        for path in (wordlist or DEFAULT_WORDLIST):
            if self.respect_robots and any(path.lstrip("/").startswith(d) for d in disallowed):
                continue
            self.rate_limiter.wait()
            status = self._probe(base_url, path)
            if status is not None and status < 400:
                hint = next(
                    (cat for key, cat in _PATH_CATEGORY_HINTS if key in path.lower()),
                    "endpoint",
                )
                findings.append(Finding(
                    module=self.name,
                    title=f"Discovered: /{path} ({status})",
                    severity=Severity.INFO,
                    category=FindingCategory.RECON,
                    target=target,
                    description=f"Path responded with HTTP {status} — categorised as {hint}.",
                    extra={"path": path, "status": status, "category_hint": hint},
                ))
        return findings

    def _check_sitemap(self, base_url: str, target: str) -> list[Finding]:
        try:
            status, body = self._fetch(urljoin(base_url, "/sitemap.xml"))
        except Exception:
            return []
        if status != 200:
            return []

        locs = re.findall(r"<loc>(.*?)</loc>", body)[:50]
        return [
            Finding(
                module=self.name,
                title=f"Listed in sitemap.xml: {loc}",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description="Directly listed in sitemap.xml — no probing needed for this entry.",
                extra={"source": "sitemap.xml"},
            )
            for loc in locs
        ]

    def _parse_robots(self, base_url: str) -> list[str]:
        try:
            status, body = self._fetch(urljoin(base_url, "/robots.txt"))
        except Exception:
            return []
        if status != 200:
            return []

        disallowed = []
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip().lstrip("/")
                if path:
                    disallowed.append(path)
        return disallowed

    def _probe(self, base_url: str, path: str) -> int | None:
        try:
            status, _ = self._fetch(urljoin(base_url, "/" + path))
            return status
        except Exception:
            return None

    def _default_fetch(self, url: str) -> tuple[int, str]:
        # Session/auth headers (if any are configured for this engagement —
        # see Engagement.auth_headers()) are merged in here so this module
        # can discover endpoints behind a login wall, not just publicly
        # reachable ones. Empty by default, identical to today's
        # unauthenticated-only behaviour when nothing is configured.
        headers = {"User-Agent": "redteam-toolkit/0.1"}
        headers.update(self.engagement.auth_headers())
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, ""
