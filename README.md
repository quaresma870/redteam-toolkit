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
the full roadmap. **Sprint 0 (this release) is foundation only**: the
authorization/scope engine and audit logging that every later module depends
on. There are no scanning modules yet.

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
│   ├── cli.py                   # init, validate-scope, status
│   └── core/
│       ├── authorization.py     # authorization.yml schema + CIDR/wildcard scope matching
│       ├── audit_log.py         # hash-chained, append-only audit log
│       ├── engagement.py        # Engagement — the structural scope-enforcement gate
│       └── models.py            # Finding, ModuleResult, EngagementReport
├── tests/
│   ├── fixtures/mock_target/    # local-only mock HTTP target for CI (never real targets)
│   └── test_redteam_toolkit.py
├── docs/
│   ├── legal-and-ethics.md
│   └── methodology.md
└── .github/workflows/ci.yml
```

---

## Changelog

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
