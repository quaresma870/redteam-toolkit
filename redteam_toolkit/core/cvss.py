"""
CVSS scoring — guarantees every Finding across every module category
(recon, vuln-id, active) has a CVSS score before it reaches a report.

Findings backed by a published CVE (cve_correlation) carry their real,
NVD-sourced score already. Everything else — default credentials, weak
TLS, missing headers, zone transfer exposure, confirmed SQLi/XSS/SSRF/
traversal/open-redirect — gets a representative score from the internal
rubric below, based on the severity the producing module already assigned.

See docs/cvss-rubric.md for the full rationale and caveats.
"""

from __future__ import annotations

from redteam_toolkit.core.models import Finding, Severity

INTERNAL_RUBRIC: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}


def ensure_cvss_score(finding: Finding) -> Finding:
    """Assigns a score from the internal rubric if the finding doesn't
    already carry one (e.g. from an NVD-sourced CVE record). Mutates and
    returns the same Finding."""
    if finding.cvss_score is None:
        finding.cvss_score = INTERNAL_RUBRIC.get(finding.severity, 0.0)
    return finding


def ensure_all_scored(findings: list[Finding]) -> list[Finding]:
    """Convenience for scoring an entire findings list in one call —
    used by the report generators so no caller can forget this step."""
    for f in findings:
        ensure_cvss_score(f)
    return findings
