# Internal CVSS scoring rubric

Findings backed by a published CVE (see the `cve_correlation` module) use
that CVE's official CVSS score directly, pulled from NVD's record.

Findings without a CVE — default credentials, weak TLS configuration,
missing security headers, and (from Sprint 3) confirmed SQL injection, XSS,
SSRF, and path traversal — are assigned a representative score from this
internal rubric, based on the severity already assigned by the producing
module:

| Severity | Representative CVSS score |
|----------|----------------------------|
| CRITICAL | 9.5 |
| HIGH     | 7.5 |
| MEDIUM   | 5.5 |
| LOW      | 3.0 |
| INFO     | 0.0 |

This is a deliberately coarse mapping, not a per-finding CVSS vector
calculation. It exists so every finding in a report has *a* comparable
score for sorting and prioritisation — it does not claim CVSS-vector
precision (attack complexity, privileges required, scope, user
interaction, etc.) for findings that were never independently scored
against the full vector. If you need an exact CVSS vector for a specific
finding, calculate it directly using the
[official CVSS calculator](https://www.first.org/cvss/calculator/3.1).

See `redteam_toolkit/vuln_id/aggregate.py` for the implementation —
`ensure_cvss_score()` is called on every finding before it's included in
any report, so no finding type ships without a score.
