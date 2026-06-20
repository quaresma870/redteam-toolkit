from __future__ import annotations


class TestPathTraversalDetection:
    def test_confirmed_on_vulnerable_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.path_traversal import PathTraversalModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        m = PathTraversalModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}/vulnerable/traversal", params=["file"])

        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "CRITICAL"

    def test_no_false_positive_on_safe_mock_target(self, active_engagement_factory, mock_target):
        from redteam_toolkit.active.path_traversal import PathTraversalModule

        eng = active_engagement_factory(targets=["127.0.0.1"])
        m = PathTraversalModule(eng)
        result = m.run(f"http://127.0.0.1:{mock_target}/safe/traversal", params=["file"])

        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"

    def test_request_ceiling_per_parameter(self, active_engagement_factory):
        from redteam_toolkit.active.path_traversal import MAX_PROBES_PER_PARAM, PathTraversalModule

        eng = active_engagement_factory()
        m = PathTraversalModule(eng, fetch_fn=lambda *a: "")
        m.run("127.0.0.1", params=["file"])
        assert m.probe_count == MAX_PROBES_PER_PARAM

    def test_stops_probing_once_confirmed(self, active_engagement_factory):
        from redteam_toolkit.active.path_traversal import PathTraversalModule

        eng = active_engagement_factory()
        m = PathTraversalModule(eng, fetch_fn=lambda *a: "root:x:0:0:root:/root:/bin/bash")
        m.run("127.0.0.1", params=["file"])
        assert m.probe_count == 1  # confirmed on the first payload — stop

    def test_evidence_bounded_not_full_file_dump(self, active_engagement_factory):
        """Minimal evidence only — confirms the issue's 'not bulk file
        exfiltration' constraint at the data-handling level."""
        from redteam_toolkit.active.path_traversal import PathTraversalModule

        eng = active_engagement_factory()
        huge_body = "root:x:0:0:root:/root:/bin/bash\n" * 1000
        m = PathTraversalModule(eng, fetch_fn=lambda *a: huge_body)
        result = m.run("127.0.0.1", params=["file"])
        assert len(result.findings[0].evidence) <= 120

    def test_multiple_parameters_each_get_own_ceiling(self, active_engagement_factory):
        from redteam_toolkit.active.path_traversal import MAX_PROBES_PER_PARAM, PathTraversalModule

        eng = active_engagement_factory()
        m = PathTraversalModule(eng, fetch_fn=lambda *a: "")
        m.run("127.0.0.1", params=["file", "path"])
        assert m.probe_count == MAX_PROBES_PER_PARAM * 2

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.active.path_traversal import PathTraversalModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["active"])
        eng.confirm_active_tier("test")
        m = PathTraversalModule(eng, fetch_fn=lambda *a: "root:x:0:0")
        result = m.run("203.0.113.5", params=["file"])
        assert result.error is not None
