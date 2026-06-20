from __future__ import annotations


class TestXSSDetection:
    def test_confirmed_on_vulnerable_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.xss import XSSDetectionModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        m = XSSDetectionModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}/vulnerable/reflect", params=["q"])

        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "HIGH"

    def test_no_false_positive_on_safe_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.xss import XSSDetectionModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        m = XSSDetectionModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}/safe/reflect", params=["q"])

        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"

    def test_unique_marker_per_request(self, active_engagement_factory):
        """Each probe uses a fresh random marker — a cached/templated page
        containing a stale static string must never produce a false hit."""
        from redteam_toolkit.active.xss import XSSDetectionModule

        eng = active_engagement_factory()
        seen_payloads = []
        def fetch(target, param, payload):
            seen_payloads.append(payload)
            return ""
        m = XSSDetectionModule(eng, fetch_fn=fetch)
        m.run("127.0.0.1", params=["q", "search"])
        assert len(set(seen_payloads)) == 2  # both unique

    def test_request_ceiling_per_parameter(self, active_engagement_factory):
        from redteam_toolkit.active.xss import MAX_PROBES_PER_PARAM, XSSDetectionModule

        eng = active_engagement_factory()
        m = XSSDetectionModule(eng, fetch_fn=lambda *a: "")
        m.run("127.0.0.1", params=["q"])
        assert m.probe_count == MAX_PROBES_PER_PARAM

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.active.xss import XSSDetectionModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["active"])
        eng.confirm_active_tier("test")
        m = XSSDetectionModule(eng, fetch_fn=lambda *a: "")
        result = m.run("203.0.113.5", params=["q"])
        assert result.error is not None
