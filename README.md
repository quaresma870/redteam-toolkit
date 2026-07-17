# 🎯 redteam-toolkit

[![CI](https://github.com/quaresma870/redteam-toolkit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/quaresma870/redteam-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Authorized penetration testing toolkit — mandatory scope enforcement,
tamper-evident audit logging, non-destructive vulnerability detection.

![Dashboard showing a demo engagement's findings](docs/images/dashboard-screenshot.png)

*The dashboard above, generated from real (demo) engagement data — see
[`redteam-toolkit demo`](#quickstart) to produce this yourself in one command.*

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

- No unattended `vuln-id`/`active` automation — those always require a single,
  attended, deliberate invocation (`active` additionally requires `--confirm`
  every single time). `schedule` exists for recurring scans, but is
  deliberately `recon`-only — see `schedule --help` for why
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

### See it work in 10 seconds — no setup

```bash
pip install -r requirements.txt
PYTHONPATH=. python -m redteam_toolkit.cli demo
```

Starts a local, deliberately vulnerable target, runs a real recon + active
scan against it, and opens the dashboard with the real findings — no
`authorization.yml` to write by hand, no real target to find or stand up.
Everything it generates (`redteam-toolkit-demo/demo-authorization.yml`) is
clearly marked `DEMO — do not use for real engagements` and scoped only to
`127.0.0.1`, so it can never be mistaken for a real engagement's
authorization file. Use `--no-serve` to skip the dashboard and just see the
scan output.

### A real engagement

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
PYTHONPATH=. python -m redteam_toolkit.cli recon example.com --modules subdomain_takeover   # dangling CNAME check

# Batch scanning — one or more targets directly, and/or a file with one
# target per line (# comments and blank lines ignored). Each target is
# still scoped, rate-limited, and scanned independently and in sequence
# — never in parallel. Works the same way for `vuln-id` and `active`.
PYTHONPATH=. python -m redteam_toolkit.cli recon a.example.com b.example.com c.example.com
PYTHONPATH=. python -m redteam_toolkit.cli recon --targets-file targets.txt --modules passive_dns

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

# 8b. What's changed since the last scan? Run IDs are numeric (shown when
#     a scan saves to --db) or the keywords 'latest'/'previous'. Exits
#     non-zero if any new CRITICAL/HIGH finding appeared — convenient in CI.
PYTHONPATH=. python -m redteam_toolkit.cli diff previous latest --db engagements.db
PYTHONPATH=. python -m redteam_toolkit.cli diff 3 7 --db engagements.db --json

# 8c. Triage a finding — mark it false-positive/accepted-risk/remediated so it
#     stops counting toward diff's regression exit code on future re-scans.
#     Never hides the finding — it still shows up in diff/report, just marked.
#     Finding IDs come from a report, `diff --json`, or the dashboard.
PYTHONPATH=. python -m redteam_toolkit.cli triage 42 --status accepted-risk \
  --reason "Client approved, ticket JIRA-123" --until 2026-12-31 --db engagements.db
PYTHONPATH=. python -m redteam_toolkit.cli triage 42 --status open --db engagements.db  # revert

# 8d. Recurring recon scans (e.g. a weekly subdomain-takeover sweep) — deliberately
#     recon-only, never vuln-id or active. Runs immediately, then on the given
#     cadence; stops on its own once authorization.yml's window expires.
PYTHONPATH=. python -m redteam_toolkit.cli schedule app.acme-staging.com \
  --cron "0 6 * * 1" --modules subdomain_takeover --db engagements.db

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

### Authenticated scanning (targets behind a login wall)

Every module scans unauthenticated by default. For applications that require
a login to reach the parts of the attack surface actually worth testing,
supply session credentials (a cookie, a bearer token, or any other
header-based auth) that get attached to every HTTP request `recon`,
`vuln-id`, and `active` make — via `authorization.yml`:

```yaml
session_auth:
  headers:
    Cookie: "session=<your-real-session-token>"
```

and/or per-invocation via `--session-header` (repeatable, merges with and
overrides the file's headers on a same-name conflict):

```bash
PYTHONPATH=. python -m redteam_toolkit.cli recon app.acme.com \
  --session-header "Cookie: session=abc123" \
  --modules endpoint_discovery,http_posture
```

**These are credentials — treated with the same care as everything else
security-sensitive in this toolkit:**
- Never echoed to the console, never written to the audit log, never
  rendered into a report. The object holding them overrides its own
  `repr()`/`str()` to redact values, so an accidental print/log call
  anywhere in the codebase can't leak a live token by mistake.
- Don't commit `authorization.yml` with a real session token in it to
  version control — treat it the same as any other live credential
  (a `.gitignore` entry, a secrets manager, or pull it from an environment
  variable into the YAML at deploy time, whichever fits your workflow).
- A session token is typically short-lived. If scans against an
  authenticated target start failing partway through a long engagement,
  the token has probably expired — re-authenticate and supply a fresh one,
  rather than assuming the target itself changed.

### Scanning targets with a self-signed certificate

By default, every HTTP-based module (`http_posture`, `web_fingerprint`,
`endpoint_discovery`, and the active-tier injection detectors) verifies TLS
certificates the same way a browser would — a target with a self-signed or
otherwise unverifiable certificate (extremely common for internal or
staging infrastructure) fails with a generic "request failed" finding
rather than actually scanning it.

For an authorized engagement against exactly this kind of target, pass
`--insecure` to `recon`, `vuln-id`, or `active`:

```bash
PYTHONPATH=. python -m redteam_toolkit.cli vuln-id https://internal-app.staging \
  --insecure --modules http_posture
```

This prints a clear warning every time it's used and is **deliberately
CLI-only** — there is no `authorization.yml` equivalent, unlike
`session_auth`. Disabling certificate verification is a real security
tradeoff that should be a conscious choice made fresh for each invocation
(the same way `curl -k` works), not something that could be silently
carried over from an old config file into a future engagement against a
target that does have a valid certificate.

### The audit log

Every action — allowed or refused — is recorded in `<engagement_id>.audit.jsonl`,
hash-chained so that editing, deleting, or reordering any *historical* entry
is detectable:

```python
from redteam_toolkit.core.audit_log import verify_log_integrity

valid, broken_at_line, entry_count = verify_log_integrity("acme-2026-q2.audit.jsonl")
```

`redteam-toolkit status` runs this check and reports it automatically — verified
end-to-end against a real, manually-edited log file (a sed-style field edit, a
deleted line, and reordered lines), not just unit-tested against constructed
data:

```
$ redteam-toolkit status --authorization authorization.yml
...
Audit log: TAMPERED — chain broken at line 2 (1 entries verified before the break)
```

**Known limitation, confirmed by the same audit**: hash-chaining detects
modification, insertion, or reordering of any entry — but it **cannot detect
truncation** (deletion of the *most recent* entries), since there's nothing
after the cut left to reference what's missing. This is mathematically
inherent to a pure hash chain with no external anchor — the same limitation
applies to e.g. `git` commit history, which is why a remote and a second
independent clone exist as that anchor. If you need real protection against
truncation specifically, independently record the `entry_count` value
out-of-band after key milestones (a client deliverable, a ticket comment, a
value shipped to an external log aggregator) and compare it on a later check.

---

## Project structure

```
redteam-toolkit/
├── redteam_toolkit/
│   ├── cli.py                   # init, validate-scope, status, recon, vuln-id, active
│   ├── scheduler.py             # `schedule` command — recon-only recurring scans
│   ├── core/
│   │   ├── authorization.py     # authorization.yml schema + CIDR/wildcard scope matching + SessionAuth
│   │   ├── audit_log.py         # hash-chained, append-only audit log
│   │   ├── engagement.py        # Engagement — scope gate + active-tier confirmation gate
│   │   ├── models.py            # Finding, ModuleResult, EngagementReport
│   │   ├── netutil.py           # bare-host extraction for scope checks on URL-style targets
│   │   ├── rate_limit.py        # RateLimiter + GlobalRateBudget — hard session-wide ceiling
│   │   ├── cvss.py              # project-wide CVSS scoring rubric
│   │   ├── history.py           # SQLite persistence of module results, keyed by engagement_id
│   │   ├── diff.py              # compare findings between two persisted scan points — `diff` command
│   │   └── status.py            # finding disposition tracking (false-positive/accepted-risk/remediated) — `triage` command
│   ├── templates/                # engagement-type authorization.yml templates (init --template)
│   ├── reports/
│   │   ├── build.py             # assembles a full EngagementReport from authorization + history
│   │   ├── html.py              # self-contained HTML report (zero external requests)
│   │   └── pdf.py                # PDF export via reportlab — no headless-browser dependency
│   ├── dashboard/
│   │   └── app.py                # read-only FastAPI dashboard — not authenticated by default
│   ├── demo/
│   │   └── target_server.py      # deliberately vulnerable local server for `demo` command — see #53
│   ├── recon/
│   │   ├── base.py              # BaseReconModule — shared run() scope/rate-limit gate
│   │   ├── port_scanner.py
│   │   ├── fingerprint.py
│   │   ├── passive_dns.py
│   │   ├── active_dns.py        # ActiveDNSModule + ZoneTransferModule
│   │   ├── web_fingerprint.py
│   │   ├── endpoint_discovery.py
│   │   ├── subdomain_takeover.py   # dangling CNAME detection — see recon/data/README.md
│   │   └── data/
│   │       └── can_i_take_over_xyz_fingerprints.json   # vendored, CC-BY-4.0, attributed
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

## CI

On every push/PR: lint → unit tests (390+, mocked/isolated) → build the real
wheel, install it in a clean venv, and run a **real integration test** —
every README-documented command, against the actual installed CLI via real
subprocess calls, not `CliRunner` against the dev source tree: `init` for
all three engagement templates, `validate-scope`, `status`,
`recon`/`vuln-id`/`active` against a real mock target (including
`--targets-file` and `--session-header`), `diff` (text and `--json`),
`report --format both`, and `serve` with real HTTP requests against its
actual API routes. A separate `e2e-smoke-test` job covers a similar flow via
`CliRunner` for faster iteration during development.

This exists because two real bugs (the `serve` dashboard-dependency
message, and a JSON-corrupting `console.print()` call in `diff --json`)
both shipped past 390+ passing unit tests, because those tests exercise
the CLI in-process, never a real subprocess against a real installed
wheel. Confirmed this job actually catches a regression by temporarily
reintroducing the JSON corruption bug and watching both this job and the
relevant unit test fail, before relying on it.

---

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

MIT for the software itself — see [LICENSE](LICENSE). Using this tool against
any system requires separate, explicit authorization from that system's owner.
