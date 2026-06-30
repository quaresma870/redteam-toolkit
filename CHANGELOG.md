# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features, status, and roadmap.

### v0.7.2
- feat: **CI integration-test tier** — extended the build job's minimal smoke test into a real
  integration test covering every README-documented command against the actual installed wheel via
  real subprocess calls: `init` for all three engagement templates, `validate-scope`, `status`,
  `recon`/`vuln-id`/`active` against a real mock target (including `--targets-file` and
  `--session-header`), `diff` (text and `--json`), `report --format both`, and `serve` with real
  HTTP requests — closes #44.
- fix: **`diff --json` output was real, reproduced JSON corruption** — `console.print(json.dumps(...))`
  wraps text to the terminal width by default, silently injecting real newline characters into the
  middle of long JSON string values (a finding's description or evidence text), producing output
  that fails `json.loads()`. Fixed by using plain `print()` for this output path. Found by piping
  the new integration script's own `--json` output through a real JSON parser, not by reading the
  code — and verified to actually catch a regression on real CI before relying on it, including a
  bug in the verification script itself that initially swallowed the parse failure alongside an
  unrelated expected non-zero exit.

### v0.7.1
- fix: **`serve`'s missing-dependency error message had the same bug just found and fixed in the
  sibling secureaudit repo** — only `import uvicorn` was guarded (a present-uvicorn/absent-fastapi
  combination would dump a raw, unhandled traceback), and the message's own
  `redteam-toolkit[dashboard]` had its square brackets silently stripped by Rich's console markup
  parser instead of printed literally.
- fix: the CLI's own messages pointed at `docs/legal-and-ethics.md`, a real file in this repo but
  not bundled into the pip package — anyone who installed via `pip install redteam-toolkit` rather
  than cloning the source had no local copy of that path. Now points at the GitHub blob URL, which
  resolves regardless of install method.
- chore: verified every README-documented command end-to-end against a real installed wheel in a
  clean venv (not just the dev source tree) — `init` for all three engagement templates,
  `validate-scope`, `status`, `recon`/`vuln-id`/`active` against a real mock target including
  `--targets-file` and `--session-header`, `report --format both`, `diff` (text and `--json`), and
  `serve`'s actual API routes with real persisted data.

### v0.7.0
- feat: **subdomain takeover detection** (`subdomain_takeover` recon module) — resolves each
  candidate subdomain's CNAME chain and matches it against a vendored copy of the
  community-maintained EdOverflow/can-i-take-over-xyz fingerprint database (CC-BY-4.0, attributed
  in `recon/data/README.md`), filtered to the 26 entries the project currently marks vulnerable.
  That filter matters: GitHub Pages, Heroku, Netlify, and Shopify have all since fixed the classic
  takeover vector via mandatory domain verification and are deliberately excluded, confirmed
  against the live, current data rather than assumed from older security folklore. AWS S3 and a
  wide family of Microsoft Azure services remain genuinely exploitable today and are included.
- feat: **multi-target batch scanning** — `recon`/`vuln-id`/`active` now accept multiple targets
  directly and/or via a new `--targets-file` option, scanned independently and in sequence (never
  in parallel — rate limiting and scope checking stay genuinely per-target). Single-target output
  is unchanged.
- feat: **diff between scans** (`diff` command) — ports secureaudit's proven
  `secureaudit diff previous latest` pattern (stable-key matching, same new/resolved/unchanged
  shape, exit-1-on-regression CI convenience), adapted to this project's accumulating
  per-module-per-invocation history: "the state as of run X" means each module's most recent
  invocation at or before that point, not a union of every historical invocation — otherwise a
  fixed finding could never show as resolved.
- feat: **authenticated scanning** — session/cookie support for targets behind a login wall.
  `authorization.yml`'s optional `session_auth.headers` and/or a new `--session-header` CLI flag
  (repeatable, on `recon`/`vuln-id`/`active`) get merged into every HTTP request
  `endpoint_discovery`, `http_posture`, and `web_fingerprint` make. Session credentials are
  redacted from any `repr()`/`str()` and never reach the audit log or any report, by construction
  — verified end-to-end against a real session-cookie-protected route added to the mock-target test
  server, not just unit-tested in isolation.
- fix: `pyproject.toml`'s `package-data` only listed `templates/*.yml.example` — the new
  `recon/data/*.json` fingerprint file would have been silently missing from any `pip install`ed
  copy of this package.
- chore: `core/history.py`'s `_ensure_schema` made public (`ensure_schema`) now that it's genuinely
  used across two modules (`history.py` and the new `core/diff.py`), not kept private just by
  leftover convention.

### v0.6.0 — Sprint 5: Production Hardening & Distribution
- feat: **global rate budget** (`core/rate_limit.GlobalRateBudget`) — a hard, session-wide request
  ceiling that no module can exceed regardless of internal bugs, on top of each module's own
  per-second pacing. Wired into every module that loops over parameters/wordlists
  (`port_scanner`, `active_dns`, `endpoint_discovery`, `default_credentials`, and — newly rate-
  limited for the first time — `sqli_detection`, `xss_detection`, `open_redirect_detection`,
  `ssrf_detection`, `path_traversal_detection`). Configurable via `authorization.yml`'s optional
  `rate_limits` section, defaults to 5000 requests/session at 100/sec. Visible in `status` output.
  Verified with a simulated runaway module (1000 fake parameters against a 10-request ceiling) —
  stopped at exactly 10, not 1000.
- feat: `docs/methodology.md` expanded with full PTES phase mapping and OWASP WSTG category
  mapping, a step-by-step engagement walkthrough, and an explicit list of what's deliberately not
  automated (threat modeling, business logic testing, manual finding verification).
- feat: `docs/legal-and-ethics.md` expanded — what "authorization" needs to actually look like,
  jurisdiction-illustrative statutes, the active-tier confirmation's rationale, guidance for
  testing your own systems (cloud shared-responsibility boundaries, production availability risk),
  and what the audit log does and doesn't prove.
- feat: `redteam_toolkit/templates/` — three engagement-type authorization templates (web-app,
  network, internal-redteam), each reducing boilerplate while still requiring every
  scope/date/confirmation-phrase field to be filled in by hand. `init --template <type>` writes
  one; bundled in the wheel via `package-data` and verified present in a real build, not just
  assumed.
- feat: `.github/workflows/publish.yml` — PyPI trusted publishing (OIDC, no stored token) on
  `v*.*.*` tags, with a tag-vs-pyproject.toml version check and a check that all three template
  files actually made it into the built wheel before publishing.
- feat: end-to-end smoke test CI job — runs `init --template` → fill in → `validate-scope` →
  `status` → `recon --db` → `active --db` (against the real mock target's known-vulnerable SQLi
  endpoint) → `report --format both`, asserting the SQLi finding appears in both the CLI output
  and the generated HTML report, and that the PDF has a valid header. One connected flow, not
  isolated unit tests.
- feat: `homebrew-redteam-toolkit` tap — `Formula/redteam-toolkit.rb` with real sha256 hashes
  fetched from PyPI's JSON API for every dependency (including `cryptography`, which needs
  `depends_on "rust" => :build` since its current release only ships arm64 macOS wheels, not a
  universal one — confirmed by checking PyPI's actual wheel list, not assumed); `bin/update-formula.sh`
  for post-release hash updates. Formula syntax checked with `ruby -c`; honestly documented as
  **not yet verified via a real `brew install`** since no macOS/Homebrew environment exists in
  this project's development setup.
- test: 31 new tests — `GlobalRateBudget` ceiling enforcement (including a concurrent-access test
  confirming the ceiling holds exactly under threading, never overshoots), `RateLimiter`
  integration with the global budget, `authorization.yml`'s `rate_limits` parsing, every
  `init --template` variant (writes correctly, never pre-fills scope/dates/confirmation, validates
  against the real schema once filled in, commented-out rate-limit examples don't silently
  activate), and `status` command output.

### v0.5.0 — Sprint 4: Reporting
- feat: `core/history.py` — SQLite persistence keyed by `engagement_id`, so module results from
  separate `recon`/`vuln-id`/`active` CLI invocations (across an entire engagement) combine into
  one report. Migrates existing databases automatically (verified against a hand-built
  pre-migration schema, not just the happy path).
- feat: `reports/build.py` — assembles a full `EngagementReport` from the validated
  `Authorization`, the audit log integrity check, and persisted module results; persists an
  integrity snapshot back to the database so the dashboard can reconstruct an equivalent report
  later without access to the original `authorization.yml`/audit log files.
- feat: `reports/html.py` — self-contained HTML report (zero external requests, not even a CDN):
  executive summary with risk posture, scope & authorization recap, modules-run summary,
  technical findings sorted by severity.
- feat: `reports/pdf.py` — PDF export via `reportlab` (pure-Python, no headless-browser or
  Cairo/Pango system dependency) with equivalent content to the HTML report.
- feat: `core/cvss.py` — CVSS scoring rubric generalised project-wide (previously vuln-id-only);
  `vuln_id/aggregate.py` re-exports it for backward compatibility. Confirmed against a real
  pipeline run that `zone_transfer`'s HIGH-severity finding (which never sets an explicit score)
  correctly receives the rubric's 7.5 when a report is built.
- feat: `dashboard/app.py` — read-only FastAPI dashboard (`redteam-toolkit serve`), mirroring this
  portfolio's existing dashboard pattern; not authenticated by default, same caution as the others.
- feat: CLI — `--db` added to `recon`/`vuln-id`/`active` to persist results; new `report` command
  (`--format html|pdf|both`); new `serve` command.
- fix: a real, self-referential bug caught by a new test before merge — the HTML report embeds
  the full `EngagementReport` as JSON inside a `<script>` tag for potential client-side use, but
  serialised it with `json.dumps()` directly. A finding's `evidence` field can contain the exact
  payload being reported on (e.g. an XSS detection's raw `<script>` tag) — if that string contains
  the literal sequence `</script`, it breaks out of the script tag and injects raw HTML into the
  report itself. Fixed by escaping `</` to `<\\/` before embedding (valid JSON either way, since
  JSON doesn't require forward slashes to be escaped but permits it). The exact same class of bug
  was also fixed in the dashboard's findings table, which rendered finding title/target/module
  content unescaped.

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
