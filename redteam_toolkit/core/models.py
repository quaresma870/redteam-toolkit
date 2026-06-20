"""
Core data models — mirrors the clean dataclass pattern used throughout this
portfolio's other tools, adapted for engagement-scoped penetration testing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(StrEnum):
    RECON = "recon"
    VULN_ID = "vuln-id"
    ACTIVE = "active"


@dataclass
class Finding:
    module: str
    title: str
    severity: Severity
    category: FindingCategory
    target: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "extra": self.extra,
        }


@dataclass
class ModuleResult:
    module: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0


@dataclass
class EngagementReport:
    engagement_id: str
    target_scope: list[str]
    authorized_by: str
    client: str
    window_start: str
    window_end: str
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    module_results: list[ModuleResult] = field(default_factory=list)
    audit_log_integrity_ok: bool | None = None
    audit_log_entry_count: int = 0

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for mr in self.module_results:
            findings.extend(mr.findings)
        return findings

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "target_scope": self.target_scope,
            "authorized_by": self.authorized_by,
            "client": self.client,
            "window": {"start": self.window_start, "end": self.window_end},
            "started_at": self.started_at.isoformat(),
            "severity_counts": self.counts_by_severity(),
            "audit_log": {
                "integrity_ok": self.audit_log_integrity_ok,
                "entry_count": self.audit_log_entry_count,
            },
            "modules": [
                {
                    "module": mr.module,
                    "error": mr.error,
                    "duration_ms": mr.duration_ms,
                    "findings": [f.to_dict() for f in mr.findings],
                }
                for mr in self.module_results
            ],
        }
