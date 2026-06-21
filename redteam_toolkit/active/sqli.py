"""
SQL injection detection — error-based probing only. Confirms the
vulnerability class exists by checking for a database error signature;
never extracts data, never enumerates tables/columns, never uses a
discovered injection to actually read or modify anything.

Bounded: at most MAX_PROBES_PER_PARAM probes per parameter, stopping as
soon as one confirms the finding for that parameter.
"""

from __future__ import annotations

import urllib.parse
import urllib.request

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.core.rate_limit import RateLimiter
from redteam_toolkit.recon.base import BaseReconModule

DEFAULT_PARAMS = ["id"]
MAX_PROBES_PER_PARAM = 4
RATE_PER_SECOND = 5.0  # stricter than recon/vuln-id defaults — active-tier probing

_ERROR_PROBES = ["'", "\"", "' OR '1'='1", "1' AND '1'='1"]

_SQL_ERROR_SIGNATURES = (
    "sql syntax", "mysql_fetch", "unclosed quotation mark",
    "quoted string not properly terminated", "ora-00933", "ora-01756",
    "sqlite3::", "microsoft ole db provider for sql server",
    "warning: mysql_", "valid mysql result", "pg_query()", "sqlstate",
)


class SQLInjectionModule(BaseReconModule):
    name = "sqli_detection"
    category = "active"

    def __init__(self, engagement, fetch_fn=None, timeout: float = 5.0, rate_per_second: float = RATE_PER_SECOND):
        super().__init__(engagement)
        self.timeout = timeout
        self._fetch = fetch_fn or self._default_fetch
        self.rate_limiter = RateLimiter(rate_per_second, global_budget=engagement.rate_budget)
        self.probe_count = 0  # exposed for tests to assert the request-count ceiling

    def scan(self, target: str, params: list[str] | None = None) -> list[Finding]:
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "sqli_probe", category=self.category)

        params = params or DEFAULT_PARAMS
        findings = []

        for param in params:
            for probe in _ERROR_PROBES[:MAX_PROBES_PER_PARAM]:
                self.rate_limiter.wait()
                self.probe_count += 1
                body = self._fetch(target, param, probe)
                if self._has_sql_error(body):
                    findings.append(Finding(
                        module=self.name,
                        title=f"Possible SQL injection in parameter '{param}'",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.ACTIVE,
                        target=target,
                        description=f"Injecting {probe!r} into '{param}' produced a database error signature.",
                        evidence=body[:200],
                        remediation="Use parameterised queries / prepared statements for all user input.",
                        cvss_score=9.8,
                        extra={"parameter": param, "probe": probe},
                    ))
                    break  # confirmed for this parameter — stop probing it

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="No SQL injection detected",
                severity=Severity.INFO,
                category=FindingCategory.ACTIVE,
                target=target,
                description=f"Probed {len(params)} parameter(s) — no database error signatures observed.",
            ))

        return findings

    def _has_sql_error(self, body: str) -> bool:
        body_lower = body.lower()
        return any(sig in body_lower for sig in _SQL_ERROR_SIGNATURES)

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
