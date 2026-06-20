"""
Port scanner — TCP connect scan, rate-limited by default. The most basic
recon primitive: what's actually listening on the target.
"""

from __future__ import annotations

import socket

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.rate_limit import RateLimiter
from redteam_toolkit.recon.base import BaseReconModule

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

# Conservative by default — raising this requires explicit --aggressive opt-in
# at the CLI layer, never a silent default.
SAFE_RATE_PER_SECOND = 50.0
AGGRESSIVE_RATE_PER_SECOND = 200.0


class PortScannerModule(BaseReconModule):
    name = "port_scanner"

    def __init__(
        self,
        engagement,
        rate_per_second: float = SAFE_RATE_PER_SECOND,
        timeout: float = 1.0,
        connect_fn=None,
    ):
        super().__init__(engagement)
        self.rate_limiter = RateLimiter(rate_per_second)
        self.timeout = timeout
        # Injectable for testing — defaults to a real TCP connect attempt.
        self._connect = connect_fn or self._default_connect

    def scan(self, target: str, ports: list[int] | None = None) -> list[Finding]:
        self.engagement.authorize_action(self.name, target, "tcp_connect_scan", category=self.category)

        findings = []
        for port in ports or DEFAULT_PORTS:
            self.rate_limiter.wait()
            if self._connect(target, port):
                findings.append(Finding(
                    module=self.name,
                    title=f"Open port {port}/tcp",
                    severity=Severity.INFO,
                    category=FindingCategory.RECON,
                    target=target,
                    description=f"TCP port {port} is open and accepted a connection.",
                    extra={"port": port, "protocol": "tcp"},
                ))
        return findings

    def _default_connect(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return True
        except OSError:
            return False
