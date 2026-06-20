# Methodology

> This is a starter version, expanded as each sprint's modules ship.
> A fuller PTES/OWASP Testing Guide alignment is planned for Sprint 5.

## How this toolkit's categories map to a standard engagement

A typical authorized penetration test moves through phases of increasing
risk and specificity. This toolkit's `allowed_categories` mirror that:

1. **`recon`** (Sprint 1) — passive and low-risk active reconnaissance:
   network port/service discovery, DNS enumeration, web technology
   fingerprinting. Establishes what's actually there before anything else.

2. **`vuln-id`** (Sprint 2) — read-only vulnerability identification:
   correlating discovered software versions against known CVEs, TLS/SSL
   configuration analysis, HTTP security posture, default-credential
   spot-checks. No exploitation — this phase answers "what *might* be
   wrong," not "can I prove it's exploitable."

3. **`active`** (Sprint 3) — non-destructive confirmation of specific
   vulnerability classes (SQL injection, XSS, SSRF, path traversal) via
   standard probing techniques. Confirms a vulnerability exists without
   exploiting it for actual access or data.

This toolkit intentionally stops there. It does not include a fourth
"exploitation" category — turning a confirmed vulnerability into actual
access, data exfiltration, or lateral movement is outside this project's
scope, by design (see the README's "what this tool deliberately does not
do" section).

## Why the categories are gated separately

Each category requires being explicitly listed in `allowed_categories` in
`authorization.yml`. A client who authorized `recon` and `vuln-id` has not
authorized `active` — the scope gate enforces that distinction automatically,
because the risk profile of "did we see what's running" is meaningfully
different from "did we send a payload to trigger application behaviour".
