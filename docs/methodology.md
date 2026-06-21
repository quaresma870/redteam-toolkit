# Methodology

This toolkit's structure follows two widely-used penetration testing
references — the [Penetration Testing Execution Standard (PTES)](http://www.pentest-standard.org/)
for overall engagement phases, and the
[OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/)
for specific web application test categories. Neither mapping below is
exhaustive (this is a focused toolkit, not a full testing platform) — it
exists so a tester already familiar with either standard can see exactly
where each module fits and what's intentionally out of scope.

## PTES phase mapping

| PTES phase | This toolkit | Notes |
|---|---|---|
| **Pre-engagement Interactions** | `authorization.yml` + `init`/`validate-scope` | Scope, window, and authorized categories are captured as a machine-checked artifact, not just a conversation. |
| **Intelligence Gathering** | Sprint 1 — `recon` category | `port_scanner`, `fingerprint`, `passive_dns`, `active_dns`, `zone_transfer`, `web_fingerprint`, `endpoint_discovery` |
| **Threat Modeling** | Not automated | This requires human judgement about what findings actually matter to *this* client's business context — deliberately left to the analyst, not the tool. |
| **Vulnerability Analysis** | Sprint 2 — `vuln-id` category | `cve_correlation`, `tls_analyzer`, `http_posture`, `default_credentials` — read-only identification of what *might* be wrong. |
| **Exploitation** | Sprint 3 — `active` category, **partially** | `sqli_detection`, `xss_detection`, `ssrf_detection`, `open_redirect_detection`, `path_traversal_detection` confirm a vulnerability class exists via standard, non-destructive probing. This toolkit stops at confirmation — it does not extract data, execute arbitrary code, or establish persistence. |
| **Post Exploitation** | **Not implemented, by design** | Lateral movement, privilege escalation, and persistence are outside this project's scope — see the README's "what this tool deliberately does not do." |
| **Reporting** | Sprint 4 | `redteam-toolkit report` (HTML/PDF) + `serve` (dashboard) |

## OWASP WSTG category mapping

| WSTG category | Relevant module(s) |
|---|---|
| WSTG-INFO (Information Gathering) | `web_fingerprint`, `endpoint_discovery`, `passive_dns`, `active_dns` |
| WSTG-CONF (Configuration & Deployment Management) | `tls_analyzer`, `http_posture`, `zone_transfer` |
| WSTG-IDNT / WSTG-ATHN (Identity & Authentication) | `default_credentials` (spot-check only, not brute force) |
| WSTG-INPV (Input Validation) | `sqli_detection`, `xss_detection`, `path_traversal_detection` |
| WSTG-CLNT (Client-side) | `xss_detection` (reflection only — no DOM-based or stored XSS coverage) |
| WSTG-BUSL (Business Logic) | Not covered — requires application-specific human analysis |

## Why the categories are gated separately

Each category requires being explicitly listed in `allowed_categories` in
`authorization.yml`. A client who authorized `recon` and `vuln-id` has not
authorized `active` — the scope gate enforces that distinction
automatically, because the risk profile of "did we see what's running" is
meaningfully different from "did we send a payload to trigger application
behaviour." `active` additionally requires typing the engagement ID at
the moment of invocation (`--confirm`), separate from the one-time
`authorization.yml` setup — see `docs/legal-and-ethics.md`.

## A typical engagement walkthrough

1. **Pre-engagement**: client and tester agree on scope; tester runs
   `redteam-toolkit init` and fills in `authorization.yml` by hand, with
   the client's sign-off on file.
2. **Validate**: `redteam-toolkit validate-scope` confirms the file is
   structurally sound; `redteam-toolkit status` confirms the engagement
   window is currently active.
3. **Recon**: `redteam-toolkit recon <target> --db engagements.db` — safe
   by default, `--aggressive` only with explicit intent.
4. **Vulnerability identification**: `redteam-toolkit vuln-id <target> --db engagements.db`
   — read-only; `default_credentials` requires its own opt-in
   (`--check-default-creds`) even when `vuln-id` is authorized.
5. **Active detection** (only if `active` was authorized): `redteam-toolkit active <target> --confirm <engagement_id> --db engagements.db`
6. **Reporting**: `redteam-toolkit report --db engagements.db --format both`
   combines everything persisted across steps 3-5 into one report, with
   the audit log's integrity status embedded as evidence of scope
   compliance.
7. **Delivery**: the analyst reviews every finding before it reaches the
   client — this toolkit surfaces candidates, it does not replace
   professional judgement about severity, business impact, or false
   positives.

## What's deliberately not automated

- **Threat modeling** and **business logic testing** require
  understanding the *specific* application's intended behaviour — no
  generic tool can substitute for that.
- **Manual verification of every finding** before client delivery. This
  toolkit's findings are candidates for analyst review, not a final
  report on their own — see the disclaimer on every generated report.
- **Social engineering, physical security testing** — entirely different
  risk/legal categories, out of scope for this project.
