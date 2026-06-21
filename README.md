# 🎯 redteam-toolkit

[![CI](https://github.com/quaresma870/redteam-toolkit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/quaresma870/redteam-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Authorized penetration testing toolkit — mandatory scope enforcement,
tamper-evident audit logging, non-destructive vulnerability detection.

---

## ⚠️ Authorization required — read this first

**This tool will not run a single scan without a validated `authorization.yml`.**
That file records who approved the engagement, exactly which targets are in
scope, and the time window during which testing is permitted. The scope gate
re-checks every single action against that file — there is no override flag,
no `--force`, no way to scan something that isn't explicitly authorized.

Using these techniques against any system without the explicit, informed
consent of that system's owner is illegal in most jurisdictions and is not
something this project will help you do. If you don't have written
authorization for the engagement you're about to start, stop here.

Before your first real engagement, read:
- [`docs/legal-and-ethics.md`](docs/legal-and-ethics.md) — what authorization
  needs to look like and why it's mandatory
- [`docs/methodology.md`](docs/methodology.md) — how this toolkit's modules
  map onto a standard pentest methodology

### What this tool deliberately does NOT do

- No `schedule`/cron mode — every run is a single, attended, deliberate action
- No real exploitation — "active" modules confirm a vulnerability class via
  standard, non-destructive probing (the same techniques tools like Nuclei or
  a ZAP baseline scan use), then stop. No payload delivery, no data
  exfiltration beyond minimal proof, no pivoting through a confirmed flaw
- No credential brute-forcing — at most a small, curated default-credential
  spot-check, single attempt per pair, heavily rate-limited, opt-in only

---

## Status

This project is being built in public, sprint by sprint — see
[milestones](https://github.com/quaresma870/redteam-toolkit/milestones) for
the full roadmap. **All 6 sprints are complete**: authorization/scope
enforcement, reconnaissance, vulnerability identification, non-destructive
active detection, full engagement reporting, and production hardening
(global rate budget, expanded methodology/legal docs, engagement-type
templates, PyPI publish workflow, Homebrew tap).

---

## Installation

```bash
# From PyPI (once published — see CHANGELOG.md for release status)
pip install redteam-toolkit

# Optional dashboard support
pip install redteam-toolkit[dashboard]

# Via Homebrew (macOS)
brew tap quaresma870/redteam-toolkit
brew install redteam-toolkit

# From source, for development
git clone https://github.com/quaresma870/redteam-toolkit
cd redteam-toolkit
pip install -r requirements.txt
```

## Quickstart

```bash
pip install -r requirements.txt

# 0. Start from an engagement-type template (optional) — still requires
#    filling in every scope/date/confirmation field by hand
PYTHONPATH=. python -m redteam_toolkit.cli init --template web-app
# other templates: network, internal-redteam

# 1. Create a template — every field still requires manual completion
PYTHONPATH=. python -m redteam_toolkit.cli init

# 2. Fill in authorization.yml by hand: engagement_id, authorized_by,
#    scope.targets, window.start/end, confirmation_phrase. Get explicit
#    written sign-off from the target owner before going further.

# 3. Validate it
PYTHONPATH=. python -m redteam_toolkit.cli validate-scope

# 4. Check engagement status (time remaining, audit log integrity)
PYTHONPATH=. python -m redteam_toolkit.cli status

# 5. Run reconnaissance modules — every call goes through the scope gate
PYTHONPATH=. python -m redteam_toolkit.cli recon example.com
PYTHONPATH=. python -m redteam_toolkit.cli recon example.com --modules port_scanner,web_fingerprint
PYTHONPATH=. python -m redteam_toolkit.cli recon example.com --aggressive   # raises rate limits, prints a warning

# 6. Run vulnerability identification modules — read-only, no exploitation
PYTHONPATH=. python -m redteam_toolkit.cli vuln-id example.com
PYTHONPATH=. python -m redteam_toolkit.cli vuln-id example.com --modules tls_analyzer,http_posture
PYTHONPATH=. python -m redteam_toolkit.cli vuln-id example.com --modules default_credentials --check-default-creds

# 7. Run active-tier detection — requires 'active' in allowed_categories AND
#    typing the engagement ID to confirm intent, every single invocation
PYTHONPATH=. python -m redteam_toolkit.cli active example.com --confirm acme-2026-q2
PYTHONPATH=. python -m redteam_toolkit.cli active example.com --confirm acme-2026-q2 --modules sqli_detection,xss_detection

# 8. Persist results across the engagement (add --db to recon/vuln-id/active above), then report
PYTHONPATH=. python -m redteam_toolkit.cli recon example.com --db engagements.db
PYTHONPATH=. python -m redteam_toolkit.cli report --db engagements.db --format both

# 9. Browse engagement history — read-only, not authenticated by default
PYTHONPATH=. python -m redteam_toolkit.cli serve --db engagements.db
```

### authorization.yml

```yaml
engagement_id: "acme-2026-q2"
authorized_by: "Jane Doe, CISO"
authorized_contact_email: "jane@acme.com"
client: "Acme Corp"

scope:
  targets:
    - "198.51.100.0/24"
    - "*.acme-staging.com"
  excluded_targets:
    - "prod.acme.com"       # explicitly carved out, even if it matches a CIDR above
  allowed_categories: [recon, vuln-id]   # 'active' requires extra confirmation at run time

window:
  start: "2026-07-01T00:00:00Z"
  end: "2026-07-14T23:59:59Z"

confirmation_phrase: "I confirm authorization for acme-2026-q2"
```

- **CIDR and wildcard domain matching** — `198.51.100.0/24` matches any IP in
  that range; `*.acme-staging.com` matches any subdomain (and the bare domain).
- **Exclusions always win** — a target matching both an inclusion and an
  exclusion pattern is refused.
- **The window is re-checked on every action**, not just once at startup —
  an engagement that expires mid-run stops being authorized immediately.

### The audit log

Every action — allowed or refused — is recorded in `<engagement_id>.audit.jsonl`,
hash-chained so that editing, deleting, or reordering any historical entry
is detectable:

```python
from redteam_toolkit.core.audit_log import verify_log_integrity

valid, broken_at_line = verify_log_integrity("acme-2026-q2.audit.jsonl")
```

`redteam-toolkit status` runs this check and reports it automatically.

---

## Project structure

```
redteam-toolkit/
├── redteam_toolkit/
│   ├── cli.py                   # init, validate-scope, status, recon, vuln-id, active
│   ├── core/
│   │   ├── authorization.py     # authorization.yml schema + CIDR/wildcard scope matching
│   │   ├── audit_log.py         # hash-chained, append-only audit log
│   │   ├── engagement.py        # Engagement — scope gate + active-tier confirmation gate
│   │   ├── models.py            # Finding, ModuleResult, EngagementReport
│   │   ├── netutil.py           # bare-host extraction for scope checks on URL-style targets
│   │   ├── rate_limit.py        # RateLimiter + GlobalRateBudget — hard session-wide ceiling
│   │   ├── cvss.py              # project-wide CVSS scoring rubric
│   │   └── history.py           # SQLite persistence of module results, keyed by engagement_id
│   ├── templates/                # engagement-type authorization.yml templates (init --template)
│   ├── reports/
│   │   ├── build.py             # assembles a full EngagementReport from authorization + history
│   │   ├── html.py              # self-contained HTML report (zero external requests)
│   │   └── pdf.py                # PDF export via reportlab — no headless-browser dependency
│   ├── dashboard/
│   │   └── app.py                # read-only FastAPI dashboard — not authenticated by default
│   ├── recon/
│   │   ├── port_scanner.py
│   │   ├── fingerprint.py
│   │   ├── passive_dns.py
│   │   ├── active_dns.py        # ActiveDNSModule + ZoneTransferModule
│   │   ├── web_fingerprint.py
│   │   └── endpoint_discovery.py
│   ├── vuln_id/
│   │   ├── cve_correlation.py   # fingerprinted versions → NVD CVE lookup
│   │   ├── tls_analyzer.py      # protocol/cipher/cert inspection, no exploit payloads
│   │   ├── http_posture.py      # headers, cookies, CORS
│   │   ├── default_credentials.py  # curated spot-check, single attempt per pair, opt-in only
│   │   └── aggregate.py         # CVSS scoring guarantee + target/severity grouping
│   └── active/                  # requires authorization.yml's 'active' category + --confirm
│       ├── canary.py            # local-only callback listener for SSRF detection
│       ├── sqli.py              # error-based detection, bounded probes, never extracts data
│       ├── xss.py                # unique-marker reflection check, no execution step
│       ├── open_redirect.py      # Location-header check only, never follows the redirect
│       ├── ssrf.py               # canary confirmation, never pivots through a confirmed SSRF
│       └── path_traversal.py     # minimal-evidence confirmation, not bulk exfiltration
├── tests/
│   ├── fixtures/
│   │   ├── mock_target/         # local-only mock HTTP target — vulnerable/safe endpoint pairs
│   │   └── tls_server.py        # real self-signed cert generation for TLS analyzer tests
│   ├── recon/
│   ├── vuln_id/
│   ├── active/
│   ├── reports/                 # history, CVSS, HTML/PDF generators, dashboard, report CLI
│   └── test_redteam_toolkit.py  # Sprint 0 foundation tests
├── docs/
│   ├── legal-and-ethics.md
│   ├── methodology.md
│   └── cvss-rubric.md
└── .github/workflows/ci.yml
```

---

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

MIT for the software itself — see [LICENSE](LICENSE). Using this tool against
any system requires separate, explicit authorization from that system's owner.
