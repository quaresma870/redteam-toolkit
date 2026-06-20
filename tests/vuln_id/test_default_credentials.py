from __future__ import annotations

from redteam_toolkit.vuln_id.default_credentials import DEFAULT_CREDENTIALS


class TestDefaultCredentialsOptIn:
    def test_skipped_without_opt_in(self, engagement_factory):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        called = {"count": 0}
        def try_login(*a):
            called["count"] += 1
            return False
        m = DefaultCredentialModule(eng, rate_per_second=1000, try_login_fn=try_login)
        result = m.run("127.0.0.1", opt_in=False)

        assert called["count"] == 0  # never even attempted
        assert "not opted in" in result.findings[0].title.lower()

    def test_authorized_category_alone_is_not_sufficient(self, engagement_factory):
        """Being authorized for 'vuln-id' must not be treated as having
        opted into this specific, highest-risk check."""
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = DefaultCredentialModule(eng, rate_per_second=1000, try_login_fn=lambda *a: True)
        result = m.run("127.0.0.1")  # opt_in defaults to False
        assert "not opted in" in result.findings[0].title.lower()


class TestDefaultCredentialsRequestCeiling:
    """The safety property this module exists to guarantee: exactly one
    attempt per credential pair, never more, regardless of outcome."""

    def test_attempt_count_equals_credential_pair_count(self, engagement_factory):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = DefaultCredentialModule(eng, rate_per_second=1000, try_login_fn=lambda *a: False)
        m.run("127.0.0.1", opt_in=True)
        assert m.attempt_count == len(DEFAULT_CREDENTIALS)

    def test_attempt_count_unaffected_by_successes(self, engagement_factory):
        """A hit must not cause early termination OR extra retries — every
        pair gets tried exactly once regardless of what happened before it."""
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = DefaultCredentialModule(eng, rate_per_second=1000, try_login_fn=lambda *a: True)
        m.run("127.0.0.1", opt_in=True)
        assert m.attempt_count == len(DEFAULT_CREDENTIALS)

    def test_custom_credential_list_respected(self, engagement_factory):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = DefaultCredentialModule(eng, rate_per_second=1000, try_login_fn=lambda *a: False)
        custom = [("Service", "u", "p")]
        m.run("127.0.0.1", opt_in=True, credentials=custom)
        assert m.attempt_count == 1

    def test_rate_limit_applied_between_attempts(self, engagement_factory):
        import time

        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        rate = 5.0
        m = DefaultCredentialModule(eng, rate_per_second=rate, try_login_fn=lambda *a: False)

        start = time.monotonic()
        m.run("127.0.0.1", opt_in=True)
        elapsed = time.monotonic() - start

        min_expected = (len(DEFAULT_CREDENTIALS) - 1) / rate
        assert elapsed >= min_expected * 0.8


class TestDefaultCredentialsFindings:
    def test_successful_login_produces_critical_finding(self, engagement_factory):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = DefaultCredentialModule(eng, rate_per_second=1000, try_login_fn=lambda h, s, u, p: s == "Redis")
        result = m.run("127.0.0.1", opt_in=True)

        critical_findings = [f for f in result.findings if f.severity.value == "CRITICAL"]
        assert len(critical_findings) == 1
        assert "Redis" in critical_findings[0].title

    def test_no_successes_produces_single_info_finding(self, engagement_factory):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = DefaultCredentialModule(eng, rate_per_second=1000, try_login_fn=lambda *a: False)
        result = m.run("127.0.0.1", opt_in=True)
        assert len(result.findings) == 1
        assert result.findings[0].severity.value == "INFO"

    def test_default_try_login_always_returns_false(self, engagement_factory):
        """No protocol-specific client ships by default — confirms the
        documented honest behaviour rather than silently doing nothing
        while pretending to have checked."""
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["vuln-id"])
        m = DefaultCredentialModule(eng, rate_per_second=1000)  # no try_login_fn supplied
        result = m.run("127.0.0.1", opt_in=True)
        assert all(f.severity.value != "CRITICAL" for f in result.findings)

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["vuln-id"])
        m = DefaultCredentialModule(eng, try_login_fn=lambda *a: True)
        result = m.run("203.0.113.5", opt_in=True)
        assert result.error is not None

    def test_disallowed_category_refused_even_with_opt_in(self, engagement_factory):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = engagement_factory(allowed_categories=["recon"])  # vuln-id not authorized
        m = DefaultCredentialModule(eng, try_login_fn=lambda *a: True)
        result = m.run("127.0.0.1", opt_in=True)
        assert result.error is not None
        assert "category" in result.error
