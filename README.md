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
the full roadmap. **Sprints 0-3 are complete**: authorization/scope
enforcement, reconnaissance, vulnerability identification, and non-destructive
active detection. Reporting is not built yet.

---

## Quickstart (Sprint 0 — foundation)

```bash
pip install -r requirements.txt

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
│   │   └── rate_limit.py        # shared rate limiter for high-volume modules
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
│   └── test_redteam_toolkit.py  # Sprint 0 foundation tests
├── docs/
│   ├── legal-and-ethics.md
│   ├── methodology.md
│   └── cvss-rubric.md
└── .github/workflows/ci.yml
```

---

## Changelog

### v0.4.0 — Sprint 3: Active Detection
- feat: **active-tier confirmation gate** (`Engagement.confirm_active_tier()`) — on top of
  `'active'` being in `authorization.yml`'s `allowed_categories`, every CLI session must type the
  exact engagement ID via `--confirm` before any active-tier module can run. This can't be
  scripted around with a single boolean flag the way `--yes-i-am-sure` could be. Both refusal
  paths (category absent, ID mismatch) are logged with equal visibility to a success.
- feat: `sqli_detection` — error-based SQL injection detection, bounded probes per parameter,
  stops as soon as one probe confirms — never extracts data or enumerates schema
- feat: `xss_detection` — unique-marker reflected XSS detection, no execution step (no headless
  browser, ever)
- feat: `open_redirect_detection` — Location-header inspection only, never actually follows the
  externally-supplied redirect target
- feat: `ssrf_detection` — canary/callback confirmation via a new local-only `LocalCanaryListener`
  (never an external canary service), never pivots through a confirmed SSRF to reach further
  internal infrastructure
- feat: `path_traversal_detection` — confirms via a minimal, recognisable signature (`/etc/passwd`'s
  first line) rather than exfiltrating arbitrary file contents
- feat: CLI `active` command — requires `--confirm <engagement_id>` every invocation
- feat: mock target harness extended with vulnerable/safe endpoint pairs for SQLi, path traversal,
  and SSRF (XSS/open-redirect reuse Sprint 0's existing reflect/redirect pairs); the server is now
  threaded so the SSRF-vulnerable endpoint's real server-side self-fetch doesn't deadlock against a
  single-threaded accept loop
- test: 46 tests under `tests/active/` — the gate's negative-path tests are the priority (category
  absent, ID mismatch, bypassing `confirm_active_tier()` entirely, confirmation not bypassing
  scope/window, recon/vuln-id unaffected by active confirmation state), plus every detection module
  tested against both the vulnerable and safe mock-target variant with an explicit, asserted
  request-count ceiling for each

### v0.3.0 — Sprint 2: Vulnerability Identification
- feat: `cve_correlation` — fingerprinted service versions → NVD CVE lookup, CVSS-mapped severity
- feat: `tls_analyzer` — deprecated protocol/weak cipher detection, certificate expiry and
  hostname-mismatch checks, entirely passive (no Heartbleed-style exploit probes)
- feat: `http_posture` — security headers, cookie flags, CORS misconfiguration on live targets
- feat: `default_credentials` — the highest-risk module in this sprint, built conservatively:
  a small curated list (not a wordlist), exactly one attempt per pair, a stricter rate limit than
  every other module, and **mandatory explicit opt-in even when `vuln-id` is an authorized
  category** — being in scope for the category is not the same as opting into this specific check.
  No protocol-specific login client ships by default; `try_login_fn` is the extension point.
- feat: `aggregate.ensure_cvss_score()` — every finding gets a CVSS score, either from a real CVE
  record or the documented internal rubric (`docs/cvss-rubric.md`)
- feat: CLI `vuln-id` command — `default_credentials` is excluded from the default module
  selection even when explicitly named via `--modules` unless `--check-default-creds` is also passed
- fix: `TLSAnalyzerModule`'s certificate inspection initially used `ssl.getpeercert()`, which
  returns an **empty dict** whenever `verify_mode=CERT_NONE` (necessary here, since the whole
  point is to inspect untrusted/self-signed certificates without rejecting them first) — meaning
  certificate expiry and hostname checks silently never fired against any real target. Caught by
  an end-to-end test against a real generated self-signed certificate, not just injected data.
  Fixed by parsing the certificate's DER bytes directly via `cryptography` (now a runtime
  dependency, not just a test dependency) instead of relying on the stdlib's parsed-dict
  representation.
- dep: added `dnspython` (Sprint 1) and `cryptography` (this sprint) as runtime dependencies

### v0.2.0 — Sprint 1: Recon
- feat: `port_scanner` — TCP connect scan, rate-limited by default (50/sec safe, 200/sec with `--aggressive`)
- feat: `fingerprint` — banner-grab service/version identification (OpenSSH, nginx, Apache, ProFTPD, vsFTPd, Postfix)
- feat: `passive_dns` — subdomain discovery via certificate transparency logs, zero contact with the target
- feat: `active_dns` — wordlist subdomain brute force (rate-limited) + `zone_transfer` AXFR misconfiguration check
- feat: `web_fingerprint` — Server/X-Powered-By headers, lightweight CMS signature detection
- feat: `endpoint_discovery` — robots.txt/sitemap.xml parsed directly, then a curated wordlist probe with path categorisation
- feat: CLI `recon` command ties all modules together against one target, through the scope gate
- fix: `web_fingerprint`/`endpoint_discovery` accept a target that may include a scheme/port (since they need
  a full URL to make an HTTP request) — but were passing that full URL straight to the scope gate, which
  only ever matches bare hosts/IPs/domains per `authorization.yml`'s schema. A URL-style target was therefore
  *always* refused even when the bare host was correctly in scope. Fixed with a shared `extract_host()`
  helper used before every `authorize_action()` call in both modules; the original target string is still
  used for the actual HTTP request. Caught during manual end-to-end validation before any test existed —
  locked in with regression tests in both modules' test files.

### v0.1.0 — Sprint 0: Foundation & Safety
- feat: `authorization.yml` schema + validator (CIDR/wildcard scope matching, time window)
- feat: tamper-evident, hash-chained audit log
- feat: `Engagement` — the structural scope-enforcement gate every module will call through
- feat: `Finding`/`ModuleResult`/`EngagementReport` data models
- feat: CLI — `init`, `validate-scope`, `status`
- feat: local-only mock-target test harness for CI (no real network calls, ever)

---

## License

MIT for the software itself — see [LICENSE](LICENSE). Using this tool against
any system requires separate, explicit authorization from that system's owner.
