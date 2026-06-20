"""
Vuln-id aggregation — groups findings by target and severity, and
guarantees every finding has a CVSS score (either supplied directly by the
producing module, e.g. cve_correlation's NVD-sourced score, or assigned via
the internal rubric documented in docs/cvss-rubric.md).
"""

from __future__ import annotations

from collections import defaultdict

from redteam_toolkit.core.models import Finding, ModuleResult, Severity

# Representative CVSS score per severity band — used only for findings that
# don't already carry a score from a published CVE record. See
# docs/cvss-rubric.md for the full rationale.
INTERNAL_RUBRIC: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}


def ensure_cvss_score(finding: Finding) -> Finding:
    """Assigns a score from the internal rubric if the finding doesn't
    already carry one. Mutates and returns the same Finding."""
    if finding.cvss_score is None:
        finding.cvss_score = INTERNAL_RUBRIC.get(finding.severity, 0.0)
    return finding


def aggregate(module_results: list[ModuleResult]) -> dict:
    """Groups findings by target then severity, ensuring every finding has
    a CVSS score. Returns a summary dict suitable for report rendering."""
    by_target: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    total = 0

    for mr in module_results:
        for finding in mr.findings:
            ensure_cvss_score(finding)
            by_target[finding.target][finding.severity.value] += 1
            total += 1

    return {
        "total_findings": total,
        "targets": {target: dict(counts) for target, counts in by_target.items()},
    }
