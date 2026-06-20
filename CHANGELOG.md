# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features, status, and roadmap.

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
