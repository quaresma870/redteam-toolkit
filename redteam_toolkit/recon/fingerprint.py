"""
Service and version fingerprinting — banner grabbing on already-discovered
open ports. Passive extraction only: read what the service announces on
connect (or in response to one minimal, standard request for web ports).
Never sends crafted version-probe exploit payloads.
"""

from __future__ import annotations

import re
import socket

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.recon.base import BaseReconModule

# (pattern, product name) — checked in order, first match wins.
_BANNER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(rb"SSH-[\d.]+-OpenSSH[_-]([\w.]+)", re.IGNORECASE), "OpenSSH"),
    (re.compile(rb"220[ -].*ProFTPD ([\d.]+)", re.IGNORECASE), "ProFTPD"),
    (re.compile(rb"220[ -].*vsFTPd ([\d.]+)", re.IGNORECASE), "vsFTPd"),
    (re.compile(rb"220[ -].*Postfix", re.IGNORECASE), "Postfix"),
    (re.compile(rb"[Ss]erver:\s*nginx/([\d.]+)"), "nginx"),
    (re.compile(rb"[Ss]erver:\s*Apache/([\d.]+)"), "Apache"),
]

_WEB_PORTS = {80, 8080, 8000, 8888}


class FingerprintModule(BaseReconModule):
    name = "fingerprint"

    def __init__(self, engagement, timeout: float = 2.0, connect_fn=None):
        super().__init__(engagement)
        self.timeout = timeout
        self._connect = connect_fn or self._default_grab

    def scan(self, target: str, ports: list[int] | None = None) -> list[Finding]:
        self.engagement.authorize_action(self.name, target, "banner_grab", category=self.category)

        findings = []
        for port in ports or [21, 22, 25, 80, 443]:
            banner = self._connect(target, port)
            if not banner:
                continue
            product, version = self._identify(banner)
            label = f"{product} {version}".strip() if product else "unknown service"
            findings.append(Finding(
                module=self.name,
                title=f"Service on {port}/tcp: {label}",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description="Service identified via banner grab." if product else
                            "A response was received but the service could not be identified.",
                evidence=banner.decode("utf-8", errors="replace")[:200],
                extra={"port": port, "product": product, "version": version},
            ))
        return findings

    def _identify(self, banner: bytes) -> tuple[str | None, str | None]:
        for pattern, product in _BANNER_PATTERNS:
            m = pattern.search(banner)
            if m:
                version = m.group(1).decode(errors="replace") if m.lastindex else None
                return product, version
        return None, None

    def _default_grab(self, host: str, port: int) -> bytes | None:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                if port in _WEB_PORTS:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                try:
                    return sock.recv(2048)
                except TimeoutError:
                    return None
        except OSError:
            return None
