# Legal and ethical usage

## Why authorization is mandatory, not optional

The techniques this toolkit automates — port scanning, vulnerability
probing, credential checks, SQL injection/XSS/SSRF/traversal detection —
are the same techniques used in real attacks. The only thing that
distinguishes authorized security testing from a crime is **explicit,
informed, written consent from the system's owner**, scoped to specific
targets and a specific time window.

In most jurisdictions, accessing or probing a computer system without
authorization is a criminal offence regardless of intent — "I was just
testing" or "I didn't access anything" is not a reliable legal defence.
Relevant statutes include (this is illustrative, not legal advice, and
varies by jurisdiction):

- United States: the Computer Fraud and Abuse Act (CFAA)
- United Kingdom: the Computer Misuse Act 1990
- European Union: the Directive on attacks against information systems
  (2013/40/EU), plus each member state's implementing legislation
- Most other countries have equivalent computer-crime statutes

This is true even for systems you believe are owned by someone you know,
systems that appear to have no security at all, or systems you believe
are "basically yours" through a vendor or hosting relationship.

## What "authorization" needs to actually look like

A verbal "sure, go ahead" is not sufficient for any engagement that
matters. At minimum, you need:

- **A named individual with actual authority** to approve testing of the
  target systems — not just "someone at the company." For a vendor
  relationship, confirm the vendor's contract actually permits security
  testing by the client (or by you on the client's behalf) before
  assuming it does.
- **Written confirmation** — email is the practical minimum; a signed
  statement of work or a formal rules-of-engagement document is better
  for anything beyond a quick internal check.
- **An explicit list of in-scope targets.** Vague authorization ("test
  our network") leads to accidentally testing something nobody approved
  — a shared hosting IP, a third-party SaaS integration, a CDN edge node
  that isn't actually the client's infrastructure.
- **A defined time window.** Open-ended authorization ages badly and is
  hard to prove was still valid later if a dispute arises.
- **Agreement on which categories of testing are permitted.**
  Reconnaissance carries materially different risk than active
  exploitation attempts — a client may reasonably authorize one without
  the other.

This toolkit's `authorization.yml` schema exists to force all of the
above into one explicit, machine-checked file before any scan can run —
see the README's quickstart for the schema.

## The active-tier confirmation, specifically

Beyond `authorization.yml` listing `active` as an allowed category, every
single invocation of `redteam-toolkit active` requires typing out the
exact engagement ID via `--confirm`. This is deliberate friction: a
one-time authorization setup is easy to forget about weeks into a long
engagement, or to copy into a script that then runs unattended. Typing
the engagement ID each time means a human is actually present and
deliberately choosing to run the highest-risk category of check, every
time — not just relying on a flag set once at the start.

## If you're testing your own systems

Authorization still matters even when you believe you own everything in
scope:

- **Cloud infrastructure** often has shared responsibility boundaries —
  your cloud provider's underlying infrastructure is not yours to test,
  even if a VM running on it is. Most cloud providers (AWS, Azure, GCP)
  have their own penetration testing policies; check them before testing
  anything you didn't provision directly.
- **"Your" network may include third-party services** — vendor-managed
  devices, other tenants in a shared environment, a CDN or load balancer
  you don't actually control the configuration of.
- **Production systems serving real users** carry availability risk even
  from "non-destructive" testing — a rate-limited port scan can still
  trip an IDS/IPS, or a default-credential check can still lock out a
  real account if the target enforces lockout policies. Test
  non-production environments where possible.

## If you're unsure whether you have sufficient authorization

**Stop and get it in writing before proceeding.** This is not a
formality, and "I'll ask forgiveness later" is not a defence that holds
up — neither legally nor professionally.

## What this toolkit does to support accountability, not replace it

- The audit log records every action taken, allowed or refused, in a
  tamper-evident format — useful evidence of what was actually done and
  when, but not a substitute for having authorization in the first place.
- Every generated report embeds the authorized scope and window it was
  produced under, so a report is self-documenting about what was (and
  wasn't) covered.
- None of this changes the legal requirement: the audit log proves what
  you did, not that you were allowed to do it. Authorization has to exist
  *before* you run anything, in writing, from someone with the actual
  authority to grant it.
