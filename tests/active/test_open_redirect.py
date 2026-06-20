from __future__ import annotations


class TestOpenRedirectDetection:
    def test_confirmed_on_vulnerable_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.open_redirect import OpenRedirectModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        m = OpenRedirectModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}/vulnerable/redirect", params=["next"])

        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "MEDIUM"

    def test_no_false_positive_on_safe_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.open_redirect import OpenRedirectModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        m = OpenRedirectModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}/safe/redirect", params=["next"])

        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"

    def test_never_follows_the_redirect_target(self, active_engagement_factory):
        """The module must only inspect the Location header, never actually
        request the externally-supplied destination."""
        from redteam_toolkit.active.open_redirect import CANARY_TARGET, OpenRedirectModule

        eng = active_engagement_factory()
        requested_urls = []
        def fetch(target, param, payload):
            requested_urls.append(payload)
            return 302, CANARY_TARGET
        m = OpenRedirectModule(eng, fetch_fn=fetch)
        m.run("127.0.0.1", params=["next"])
        # Only the canary target itself was ever passed as a parameter value —
        # never actually dereferenced as a real outbound request by this module.
        assert all(u == CANARY_TARGET for u in requested_urls)

    def test_request_ceiling_per_parameter(self, active_engagement_factory):
        from redteam_toolkit.active.open_redirect import OpenRedirectModule

        eng = active_engagement_factory()
        m = OpenRedirectModule(eng, fetch_fn=lambda *a: (200, None))
        m.run("127.0.0.1", params=["next", "url", "redirect"])
        assert m.probe_count == 3  # exactly one probe per parameter, no retries

    def test_non_redirect_status_not_flagged(self, active_engagement_factory):
        from redteam_toolkit.active.open_redirect import OpenRedirectModule

        eng = active_engagement_factory()
        m = OpenRedirectModule(eng, fetch_fn=lambda *a: (200, None))
        result = m.run("127.0.0.1", params=["next"])
        assert result.findings[0].severity.value == "INFO"

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.active.open_redirect import OpenRedirectModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["active"])
        eng.confirm_active_tier("test")
        m = OpenRedirectModule(eng, fetch_fn=lambda *a: (302, "x"))
        result = m.run("203.0.113.5", params=["next"])
        assert result.error is not None
