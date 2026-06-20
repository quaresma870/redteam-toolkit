from __future__ import annotations


class TestSSRFDetection:
    def test_no_canary_configured_produces_info_finding(self, active_engagement_factory):
        from redteam_toolkit.active.ssrf import SSRFDetectionModule

        eng = active_engagement_factory()
        m = SSRFDetectionModule(eng)  # no canary_listener supplied
        result = m.run("127.0.0.1", params=["url"])
        assert "no canary listener" in result.findings[0].title.lower()

    def test_confirmed_on_vulnerable_mock_target_via_local_canary(self, active_engagement_factory, mock_target):
        """Uses a real local HTTP listener as the callback receiver — never
        an external canary service, per this issue's explicit requirement."""
        from redteam_toolkit.active.canary import LocalCanaryListener
        from redteam_toolkit.active.ssrf import SSRFDetectionModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        canary = LocalCanaryListener()
        try:
            m = SSRFDetectionModule(eng, canary_listener=canary, wait_seconds=1.0)
            result = m.run(f"http://127.0.0.1:{mock_target}/vulnerable/ssrf", params=["url"])
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "CRITICAL"
        finally:
            canary.shutdown()

    def test_no_false_positive_on_safe_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.canary import LocalCanaryListener
        from redteam_toolkit.active.ssrf import SSRFDetectionModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        canary = LocalCanaryListener()
        try:
            m = SSRFDetectionModule(eng, canary_listener=canary, wait_seconds=1.0)
            result = m.run(f"http://127.0.0.1:{mock_target}/safe/ssrf", params=["url"])
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "INFO"
        finally:
            canary.shutdown()

    def test_canary_tokens_are_unique_per_parameter(self, active_engagement_factory):
        from redteam_toolkit.active.canary import LocalCanaryListener
        from redteam_toolkit.active.ssrf import SSRFDetectionModule

        eng = active_engagement_factory()
        canary = LocalCanaryListener()
        try:
            urls_used = []
            def fetch(target, param, payload):
                urls_used.append(payload)
            m = SSRFDetectionModule(eng, canary_listener=canary, fetch_fn=fetch, wait_seconds=0.1)
            m.run("127.0.0.1", params=["url", "webhook"])
            assert len(set(urls_used)) == 2  # distinct canary URLs, not reused
        finally:
            canary.shutdown()

    def test_request_ceiling_per_parameter(self, active_engagement_factory):
        from redteam_toolkit.active.canary import LocalCanaryListener
        from redteam_toolkit.active.ssrf import SSRFDetectionModule

        eng = active_engagement_factory()
        canary = LocalCanaryListener()
        try:
            m = SSRFDetectionModule(
                eng, canary_listener=canary, fetch_fn=lambda *a: None, wait_seconds=0.1,
            )
            m.run("127.0.0.1", params=["url", "webhook", "callback"])
            assert m.probe_count == 3  # exactly one probe per parameter
        finally:
            canary.shutdown()

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.active.canary import LocalCanaryListener
        from redteam_toolkit.active.ssrf import SSRFDetectionModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["active"])
        eng.confirm_active_tier("test")
        canary = LocalCanaryListener()
        try:
            m = SSRFDetectionModule(eng, canary_listener=canary)
            result = m.run("203.0.113.5", params=["url"])
            assert result.error is not None
        finally:
            canary.shutdown()


class TestLocalCanaryListener:
    def test_generates_unique_urls(self):
        from redteam_toolkit.active.canary import LocalCanaryListener

        canary = LocalCanaryListener()
        try:
            url1 = canary.generate_url("token1")
            url2 = canary.generate_url("token2")
            assert url1 != url2
            assert "token1" in url1
        finally:
            canary.shutdown()

    def test_was_called_false_before_callback(self):
        from redteam_toolkit.active.canary import LocalCanaryListener

        canary = LocalCanaryListener()
        try:
            assert canary.was_called("never-called-token") is False
        finally:
            canary.shutdown()

    def test_was_called_true_after_real_callback(self):
        import urllib.request

        from redteam_toolkit.active.canary import LocalCanaryListener

        canary = LocalCanaryListener()
        try:
            url = canary.generate_url("real-token")
            urllib.request.urlopen(url, timeout=5)
            assert canary.was_called("real-token") is True
        finally:
            canary.shutdown()
