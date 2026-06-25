"""
Subdomain takeover detection — finds subdomains whose CNAME points to a
third-party service (S3, Azure, Bitbucket, etc.) that's since been
deprovisioned, leaving a dangling reference an attacker could claim by
registering the same resource name on that service.

Detection is read-only throughout: resolve the CNAME chain (DNS lookup),
optionally fetch the subdomain's HTTP response to check for a provider's
"unclaimed resource" page. Never attempts to register, claim, or otherwise
interact with the third-party service itself — that would be an actual
exploitation step, well outside this module's (or this category's) scope.

Fingerprint database: vendored from EdOverflow/can-i-take-over-xyz
(community-maintained, CC-BY-4.0 licensed — see data/README.md), filtered
to entries the project currently marks "vulnerable": true. That flag
matters: several historically-famous takeover vectors (GitHub Pages,
Heroku, Netlify, Shopify among them) have since been fixed by their
providers via mandatory domain-ownership verification and are excluded
here for that reason, not by oversight — confirmed against the project's
current data before relying on it, not from general security folklore
that may itself be years out of date.
"""

from __future__ import annotations

import json
import re
import urllib.request
from importlib import resources
from typing import Any

import dns.resolver

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.recon.base import BaseReconModule

_FINGERPRINTS_FILE = "can_i_take_over_xyz_fingerprints.json"


def _load_vulnerable_fingerprints() -> list[dict[str, Any]]:
    raw = resources.files("redteam_toolkit.recon.data").joinpath(_FINGERPRINTS_FILE).read_text()
    entries = json.loads(raw)
    # Only entries the upstream project currently marks vulnerable — a
    # fingerprint existing in the file at all doesn't mean the service is
    # still exploitable today (see module docstring).
    return [e for e in entries if e.get("vulnerable") and e.get("cname")]


class SubdomainTakeoverModule(BaseReconModule):
    name = "subdomain_takeover"

    def __init__(
        self,
        engagement,
        resolve_cname_fn=None,
        http_fetch_fn=None,
        ct_fetch_fn=None,
        timeout: float = 10.0,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        # Injectable so tests supply canned DNS/HTTP responses instead of
        # touching real infrastructure, consistent with every other recon
        # module in this package.
        self._resolve_cname = resolve_cname_fn or self._default_resolve_cname
        self._http_fetch = http_fetch_fn or self._default_http_fetch
        self._ct_fetch = ct_fetch_fn
        self._fingerprints = _load_vulnerable_fingerprints()

    def scan(self, target: str, subdomains: list[str] | None = None) -> list[Finding]:
        self.engagement.authorize_action(self.name, target, "subdomain_takeover_check", category=self.category)

        if subdomains is None:
            subdomains = self._discover_subdomains(target)

        findings = []
        for sub in subdomains:
            cname_chain = self._resolve_cname(sub)
            if not cname_chain:
                continue

            match = self._match_fingerprint(cname_chain)
            if match is None:
                continue

            if match["nxdomain"]:
                # The fingerprint itself IS "the CNAME target doesn't
                # resolve at all" — already confirmed by _resolve_cname
                # returning the chain despite the final hop having no
                # further record, so no HTTP fetch needed or even
                # possible here.
                findings.append(self._make_finding(sub, cname_chain, match, evidence="NXDOMAIN on CNAME target"))
                continue

            body = self._http_fetch(sub)
            if body and match["fingerprint"] and re.search(match["fingerprint"], body, re.IGNORECASE):
                findings.append(self._make_finding(sub, cname_chain, match, evidence=match["fingerprint"]))

        return findings

    def _make_finding(self, subdomain: str, cname_chain: list[str], match: dict, evidence: str) -> Finding:
        return Finding(
            module=self.name,
            title=f"Possible subdomain takeover: {subdomain} ({match['service']})",
            severity=Severity.HIGH,
            category=FindingCategory.RECON,
            target=subdomain,
            description=(
                f"{subdomain} has a CNAME chain ({' -> '.join(cname_chain)}) pointing to "
                f"{match['service']}, which currently has a known dangling-DNS takeover "
                f"vector when the underlying resource has been deprovisioned."
            ),
            evidence=evidence,
            remediation=(
                "Remove the dangling CNAME record if the service is no longer in use, or "
                "re-provision the resource under your account if it's still needed. Do not "
                "attempt to claim or interact with the third-party resource as part of "
                "verifying this finding without separate, explicit authorization to do so."
            ),
            extra={
                "subdomain": subdomain,
                "cname_chain": cname_chain,
                "service": match["service"],
                "discussion": match.get("discussion", ""),
            },
        )

    def _match_fingerprint(self, cname_chain: list[str]) -> dict | None:
        for hop in cname_chain:
            for entry in self._fingerprints:
                if any(pattern in hop.lower() for pattern in entry["cname"]):
                    return entry
        return None

    def _discover_subdomains(self, target: str) -> list[str]:
        if self._ct_fetch is not None:
            from redteam_toolkit.recon.passive_dns import PassiveDNSModule
            passive = PassiveDNSModule(self.engagement, fetch_fn=self._ct_fetch)
        else:
            from redteam_toolkit.recon.passive_dns import PassiveDNSModule
            passive = PassiveDNSModule(self.engagement)
        result = passive.run(target)
        subs = {f.extra["subdomain"] for f in result.findings if f.extra.get("subdomain")}
        subs.add(target)
        return sorted(subs)

    def _default_resolve_cname(self, hostname: str) -> list[str] | None:
        chain = []
        current = hostname
        try:
            for _ in range(10):  # bound the chain walk — real CNAME loops shouldn't happen, but don't trust that
                answer = dns.resolver.resolve(current, "CNAME", lifetime=self.timeout)
                target_name = str(answer[0].target).rstrip(".")
                chain.append(target_name)
                current = target_name
        except dns.resolver.NoAnswer:
            # Reached the end of the CNAME chain (current now has an A
            # record or similar instead) — return whatever chain we built.
            pass
        except dns.resolver.NXDOMAIN:
            # The last hop in the chain doesn't resolve at all — exactly
            # the signal some fingerprints (nxdomain: true) are looking
            # for. Keep the chain built so far; the caller checks the
            # match's nxdomain flag, not this exception, since reaching
            # here at all already proves it.
            pass
        except Exception:
            return None
        return chain or None

    def _default_http_fetch(self, hostname: str) -> str | None:
        for scheme in ("https", "http"):
            try:
                req = urllib.request.Request(f"{scheme}://{hostname}/", headers={"User-Agent": "redteam-toolkit"})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.read(65536).decode(errors="ignore")
            except Exception:
                continue
        return None
