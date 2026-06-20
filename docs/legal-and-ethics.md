# Legal and ethical usage

> This is a starter version. A fuller guide — covering PTES/OWASP Testing
> Guide alignment and sample engagement templates — is planned for Sprint 5.
> This page exists now because no scan command should ship without it.

## Why authorization is mandatory, not optional

The techniques this toolkit will eventually automate — port scanning,
vulnerability probing, credential checks — are the same techniques used in
real attacks. The only thing that distinguishes authorized security testing
from a crime is **explicit, informed, written consent from the system's
owner**, scoped to specific targets and a specific time window.

In most jurisdictions, accessing or probing a computer system without
authorization is a criminal offence regardless of intent — "I was just
testing" or "I didn't access anything" is not a reliable legal defence.
This is true even for systems you believe are owned by someone you know, or
systems that appear to have no security at all.

## What "authorization" needs to actually look like

A verbal "sure, go ahead" is not sufficient for any engagement that matters.
You need, at minimum:

- A named individual with the actual authority to approve testing of the
  target systems (not just "someone at the company")
- Written confirmation — email is the practical minimum, a signed
  statement-of-work is better
- An explicit list of in-scope targets — vague authorization ("test our
  network") leads to accidentally testing something nobody approved
- A defined time window — open-ended authorization ages badly and is hard
  to prove was still valid later
- Agreement on what categories of testing are permitted — reconnaissance is
  very different from active exploitation attempts in terms of risk

This toolkit's `authorization.yml` schema exists to force all of the above
into one explicit, machine-checked file before any scan can run.

## If you're testing your own systems

Authorization still matters even when you believe you own everything in
scope: cloud infrastructure often has shared responsibility boundaries (your
cloud provider's infrastructure is not yours to test), and "your" network
may include third-party services, vendor-managed devices, or other tenants
you don't have the right to test.

## If you're unsure whether you have sufficient authorization

Stop and get it in writing before proceeding. This is not a formality.
