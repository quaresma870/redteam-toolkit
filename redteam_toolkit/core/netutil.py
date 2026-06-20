"""
Network target parsing helpers.

Modules that need to construct an HTTP request (web_fingerprint,
endpoint_discovery) accept a target that may be a bare host/IP OR a full
URL with scheme and port. Scope checks must always operate on the bare
host — authorization.yml's scope.targets are hostnames/IPs/CIDRs/domains,
never full URLs — so the scheme/port must be stripped before calling
Engagement.authorize_action(), even though the original target string is
still used for the actual request.
"""

from __future__ import annotations

from urllib.parse import urlparse


def extract_host(target: str) -> str:
    """Return the bare hostname/IP from a target that may include a scheme
    and/or port. Falls back to the original string if nothing can be parsed
    out of it (e.g. it was already bare)."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target

    if ":" in target:
        host, _, maybe_port = target.rpartition(":")
        if maybe_port.isdigit() and host:
            return host

    return target
