from __future__ import annotations

import time


class TestPortScanner:
    def test_finds_open_port_against_mock_target(self, engagement_factory, mock_target):
        from redteam_toolkit.recon.port_scanner import PortScannerModule

        eng = engagement_factory()
        scanner = PortScannerModule(eng, rate_per_second=1000)
        result = scanner.run("127.0.0.1", ports=[mock_target, mock_target + 1])

        assert result.error is None
        assert len(result.findings) == 1
        assert str(mock_target) in result.findings[0].title

    def test_closed_port_produces_no_finding(self, engagement_factory):
        from redteam_toolkit.recon.port_scanner import PortScannerModule

        eng = engagement_factory()
        scanner = PortScannerModule(eng, rate_per_second=1000, connect_fn=lambda h, p: False)
        result = scanner.run("127.0.0.1", ports=[12345])
        assert result.findings == []

    def test_default_rate_does_not_exceed_cap(self, engagement_factory):
        from redteam_toolkit.recon.port_scanner import PortScannerModule

        eng = engagement_factory()
        rate = 20.0  # ports/sec
        scanner = PortScannerModule(eng, rate_per_second=rate, connect_fn=lambda h, p: False)

        ports = list(range(10))
        start = time.monotonic()
        scanner.run("127.0.0.1", ports=ports)
        elapsed = time.monotonic() - start

        # 10 probes at 20/sec should take at least ~ (10-1)/20 = 0.45s
        min_expected = (len(ports) - 1) / rate
        assert elapsed >= min_expected * 0.8  # generous tolerance for test timing jitter

    def test_out_of_scope_target_refused(self, engagement_factory):
        from redteam_toolkit.recon.port_scanner import PortScannerModule

        eng = engagement_factory(targets=["10.0.0.0/8"])
        scanner = PortScannerModule(eng, connect_fn=lambda h, p: True)
        result = scanner.run("203.0.113.5", ports=[80])
        assert result.error is not None
        assert "scope" in result.error

    def test_disallowed_category_refused(self, engagement_factory):
        from redteam_toolkit.recon.port_scanner import PortScannerModule

        eng = engagement_factory(allowed_categories=[])
        scanner = PortScannerModule(eng, connect_fn=lambda h, p: True)
        result = scanner.run("127.0.0.1", ports=[80])
        assert result.error is not None
        assert "category" in result.error

    def test_refusal_is_logged(self, engagement_factory):
        from redteam_toolkit.recon.port_scanner import PortScannerModule

        eng = engagement_factory(targets=["10.0.0.0/8"])
        scanner = PortScannerModule(eng, connect_fn=lambda h, p: True)
        scanner.run("203.0.113.5", ports=[80])
        entries = eng.audit_log.read_all()
        assert entries[-1]["allowed"] is False
