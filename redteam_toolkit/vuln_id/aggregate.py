"""
Vuln-id aggregation — groups findings by target and severity.

CVSS scoring itself now lives in core/cvss.py since it applies across
every module category (recon, vuln-id, active), not just vuln-id —
re-exported here for backward compatibility with existing imports.
"""

from __future__ import annotations

from collections import defaultdict

from redteam_toolkit.core.cvss import INTERNAL_RUBRIC, ensure_cvss_score
from redteam_toolkit.core.models import ModuleResult

__all__ = ["INTERNAL_RUBRIC", "ensure_cvss_score", "aggregate"]


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
