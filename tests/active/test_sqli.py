from __future__ import annotations


class TestSQLInjectionDetection:
    def test_confirmed_on_vulnerable_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.sqli import SQLInjectionModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        m = SQLInjectionModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}/vulnerable/sqli", params=["id"])

        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "CRITICAL"

    def test_no_false_positive_on_safe_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.sqli import SQLInjectionModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        m = SQLInjectionModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}/safe/sqli", params=["id"])

        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"

    def test_request_ceiling_per_parameter(self, active_engagement_factory):
        from redteam_toolkit.active.sqli import MAX_PROBES_PER_PARAM, SQLInjectionModule

        eng = active_engagement_factory()
        m = SQLInjectionModule(eng, fetch_fn=lambda *a: "")  # never confirms — exhausts all probes
        m.run("127.0.0.1", params=["id"])
        assert m.probe_count == MAX_PROBES_PER_PARAM

    def test_stops_probing_param_once_confirmed(self, active_engagement_factory):
        """Confirmation on the first probe must not trigger the remaining
        probes for that same parameter."""
        from redteam_toolkit.active.sqli import SQLInjectionModule

        eng = active_engagement_factory()
        m = SQLInjectionModule(eng, fetch_fn=lambda *a: "sql syntax error near")
        m.run("127.0.0.1", params=["id"])
        assert m.probe_count == 1

    def test_multiple_parameters_each_get_own_ceiling(self, active_engagement_factory):
        from redteam_toolkit.active.sqli import MAX_PROBES_PER_PARAM, SQLInjectionModule

        eng = active_engagement_factory()
        m = SQLInjectionModule(eng, fetch_fn=lambda *a: "")
        m.run("127.0.0.1", params=["id", "name"])
        assert m.probe_count == MAX_PROBES_PER_PARAM * 2

    def test_evidence_truncated(self, active_engagement_factory):
        from redteam_toolkit.active.sqli import SQLInjectionModule

        eng = active_engagement_factory()
        m = SQLInjectionModule(eng, fetch_fn=lambda *a: "sql syntax error " + "x" * 500)
        result = m.run("127.0.0.1", params=["id"])
        assert len(result.findings[0].evidence) <= 200

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.active.sqli import SQLInjectionModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["active"])
        eng.confirm_active_tier("test")
        m = SQLInjectionModule(eng, fetch_fn=lambda *a: "sql syntax")
        result = m.run("203.0.113.5", params=["id"])
        assert result.error is not None
