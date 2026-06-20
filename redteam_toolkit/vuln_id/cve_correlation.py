"""
CVE correlation — cross-references service versions identified by Sprint 1's
fingerprint module against NVD's published CVE records. Pure identification:
a finding here means "this version has known CVEs published against it",
not "we confirmed this specific instance is exploitable".
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.recon.base import BaseReconModule

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class CVECorrelationModule(BaseReconModule):
    name = "cve_correlation"
    category = "vuln-id"

    def __init__(self, engagement, query_fn=None, timeout: float = 15.0):
        super().__init__(engagement)
        self.timeout = timeout
        # Injectable so tests never make a real call to NVD.
        self._query = query_fn or self._default_nvd_query

    def scan(self, target: str, services: list[dict] | None = None) -> list[Finding]:
        """services: list of {"product", "version", "port"} — normally taken
        from the fingerprint module's findings' .extra dict."""
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "cve_correlation", category=self.category)

        if not services:
            return [Finding(
                module=self.name,
                title="No fingerprinted services to correlate",
                severity=Severity.INFO,
                category=FindingCategory.VULN_ID,
                target=target,
                description="Run the fingerprint module first to identify service versions, "
                            "then pass its results here as 'services'.",
            )]

        findings = []
        for svc in services:
            product, version = svc.get("product"), svc.get("version")
            if not product or not version:
                continue

            try:
                cves = self._query(product, version)
            except Exception:
                findings.append(Finding(
                    module=self.name,
                    title=f"CVE lookup failed for {product} {version}",
                    severity=Severity.INFO,
                    category=FindingCategory.VULN_ID,
                    target=target,
                    description="Network error querying the CVE database — informational only, "
                                "not a finding about the target.",
                ))
                continue

            for cve in cves:
                findings.append(Finding(
                    module=self.name,
                    title=f"{cve['id']} in {product} {version}",
                    severity=cvss_to_severity(cve.get("cvss")),
                    category=FindingCategory.VULN_ID,
                    target=target,
                    description=(cve.get("summary") or "")[:300],
                    cvss_score=cve.get("cvss"),
                    extra={
                        "port": svc.get("port"), "product": product,
                        "version": version, "cve_id": cve["id"],
                    },
                ))

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="No known CVEs found",
                severity=Severity.INFO,
                category=FindingCategory.VULN_ID,
                target=target,
                description=f"No known vulnerabilities found for the {len(services)} fingerprinted service(s).",
            ))

        return findings

    def _default_nvd_query(self, product: str, version: str) -> list[dict]:
        query = f"{product} {version}"
        url = f"{_NVD_URL}?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=10"
        req = urllib.request.Request(url, headers={"User-Agent": "redteam-toolkit/0.1"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read())

        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions", [])
            summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            results.append({"id": cve_id, "summary": summary, "cvss": _extract_cvss(cve.get("metrics", {}))})
        return results


def _extract_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None
