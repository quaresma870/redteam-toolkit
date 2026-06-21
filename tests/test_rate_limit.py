from __future__ import annotations

import time


class TestRateLimiter:
    def test_paces_calls_at_configured_rate(self):
        from redteam_toolkit.core.rate_limit import RateLimiter

        limiter = RateLimiter(max_per_second=10.0)
        start = time.monotonic()
        for _ in range(5):
            limiter.wait()
        elapsed = time.monotonic() - start
        min_expected = 4 / 10.0  # 4 intervals between 5 calls
        assert elapsed >= min_expected * 0.8

    def test_zero_rate_means_unlimited_local_pacing(self):
        from redteam_toolkit.core.rate_limit import RateLimiter

        limiter = RateLimiter(max_per_second=0)
        start = time.monotonic()
        for _ in range(100):
            limiter.wait()
        assert time.monotonic() - start < 0.5  # no pacing delay at all

    def test_without_global_budget_never_raises(self):
        from redteam_toolkit.core.rate_limit import RateLimiter

        limiter = RateLimiter(max_per_second=1000.0)
        for _ in range(50):
            limiter.wait()  # must not raise — no global budget wired


class TestGlobalRateBudget:
    def test_allows_up_to_ceiling(self):
        from redteam_toolkit.core.rate_limit import GlobalRateBudget

        budget = GlobalRateBudget(max_total_requests=5, max_per_second=1000.0)
        for _ in range(5):
            budget.consume()  # must not raise
        assert budget.used == 5
        assert budget.remaining == 0

    def test_raises_past_ceiling(self):
        from redteam_toolkit.core.rate_limit import GlobalRateBudget, RateBudgetExceeded

        budget = GlobalRateBudget(max_total_requests=3, max_per_second=1000.0)
        for _ in range(3):
            budget.consume()

        import pytest
        with pytest.raises(RateBudgetExceeded, match="exhausted"):
            budget.consume()

    def test_remaining_decreases(self):
        from redteam_toolkit.core.rate_limit import GlobalRateBudget

        budget = GlobalRateBudget(max_total_requests=10, max_per_second=1000.0)
        budget.consume()
        budget.consume()
        assert budget.remaining == 8

    def test_thread_safe_under_concurrent_access(self):
        """Multiple modules sharing one Engagement (and therefore one
        budget) could run threads concurrently — the ceiling must hold
        exactly, never overshoot due to a race."""
        import threading

        from redteam_toolkit.core.rate_limit import GlobalRateBudget, RateBudgetExceeded

        budget = GlobalRateBudget(max_total_requests=100, max_per_second=10000.0)
        successes = []
        lock = threading.Lock()

        def worker():
            for _ in range(50):
                try:
                    budget.consume()
                    with lock:
                        successes.append(1)
                except RateBudgetExceeded:
                    pass

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(successes) == 100  # exactly the ceiling, never more


class TestRateLimiterWithGlobalBudget:
    def test_consumes_from_global_budget(self):
        from redteam_toolkit.core.rate_limit import GlobalRateBudget, RateLimiter

        budget = GlobalRateBudget(max_total_requests=3, max_per_second=1000.0)
        limiter = RateLimiter(max_per_second=1000.0, global_budget=budget)

        limiter.wait()
        limiter.wait()
        limiter.wait()
        assert budget.used == 3

    def test_raises_when_global_budget_exhausted(self):
        from redteam_toolkit.core.rate_limit import (
            GlobalRateBudget,
            RateBudgetExceeded,
            RateLimiter,
        )

        budget = GlobalRateBudget(max_total_requests=2, max_per_second=1000.0)
        limiter = RateLimiter(max_per_second=1000.0, global_budget=budget)

        limiter.wait()
        limiter.wait()

        import pytest
        with pytest.raises(RateBudgetExceeded):
            limiter.wait()

    def test_simulated_runaway_module_stopped_by_global_ceiling(self):
        """The exact scenario the acceptance criteria describes: a module
        that loops far beyond its own intended bound is still stopped by
        the shared, engagement-wide ceiling."""
        from redteam_toolkit.core.rate_limit import (
            GlobalRateBudget,
            RateBudgetExceeded,
            RateLimiter,
        )

        budget = GlobalRateBudget(max_total_requests=10, max_per_second=10000.0)
        limiter = RateLimiter(max_per_second=10000.0, global_budget=budget)

        attempts = 0
        with __import__("pytest").raises(RateBudgetExceeded):
            for _ in range(10_000):  # a 'runaway' loop far beyond any sane bound
                limiter.wait()
                attempts += 1

        assert attempts == 10  # stopped exactly at the ceiling, not 10,000


class TestAuthorizationRateLimitsParsing:
    def test_no_rate_limits_section_is_none(self, tmp_path):
        from redteam_toolkit.core.authorization import load_authorization

        path = tmp_path / "authorization.yml"
        path.write_text(_minimal_auth_yaml())
        auth = load_authorization(path)
        assert auth.rate_limits is None

    def test_valid_rate_limits_parsed(self, tmp_path):
        from redteam_toolkit.core.authorization import load_authorization

        path = tmp_path / "authorization.yml"
        path.write_text(_minimal_auth_yaml(extra="rate_limits:\n  max_total_requests: 2000\n  max_per_second: 50\n"))
        auth = load_authorization(path)
        assert auth.rate_limits.max_total_requests == 2000
        assert auth.rate_limits.max_per_second == 50.0

    def test_invalid_rate_limits_raises(self, tmp_path):
        from redteam_toolkit.core.authorization import AuthorizationError, load_authorization

        path = tmp_path / "authorization.yml"
        path.write_text(_minimal_auth_yaml(extra="rate_limits:\n  max_total_requests: not-a-number\n  max_per_second: 50\n"))

        import pytest
        with pytest.raises(AuthorizationError, match="rate_limits"):
            load_authorization(path)


class TestEngagementRateBudgetWiring:
    def test_engagement_uses_default_budget_when_unconfigured(self, tmp_path):
        from redteam_toolkit.core.authorization import load_authorization
        from redteam_toolkit.core.engagement import Engagement
        from redteam_toolkit.core.rate_limit import (
            DEFAULT_MAX_PER_SECOND,
            DEFAULT_MAX_TOTAL_REQUESTS,
        )

        path = tmp_path / "authorization.yml"
        path.write_text(_minimal_auth_yaml())
        auth = load_authorization(path)
        eng = Engagement(auth, tmp_path / "test.audit.jsonl")

        assert eng.rate_budget.max_total_requests == DEFAULT_MAX_TOTAL_REQUESTS
        assert eng.rate_budget.max_per_second == DEFAULT_MAX_PER_SECOND

    def test_engagement_uses_configured_budget(self, tmp_path):
        from redteam_toolkit.core.authorization import load_authorization
        from redteam_toolkit.core.engagement import Engagement

        path = tmp_path / "authorization.yml"
        path.write_text(_minimal_auth_yaml(extra="rate_limits:\n  max_total_requests: 42\n  max_per_second: 7\n"))
        auth = load_authorization(path)
        eng = Engagement(auth, tmp_path / "test.audit.jsonl")

        assert eng.rate_budget.max_total_requests == 42
        assert eng.rate_budget.max_per_second == 7.0


def _minimal_auth_yaml(extra: str = "") -> str:
    import datetime
    now = datetime.datetime.now(datetime.UTC)
    return f"""engagement_id: "rate-limit-test"
authorized_by: "Test User"
authorized_contact_email: "test@example.com"
client: "Test Co"
scope:
  targets: ["127.0.0.1"]
  allowed_categories: ["recon"]
window:
  start: "{(now - datetime.timedelta(hours=1)).isoformat()}"
  end: "{(now + datetime.timedelta(days=1)).isoformat()}"
confirmation_phrase: "confirmed"
{extra}"""


class TestStatusCommandShowsRateBudget:
    def test_default_budget_shown(self, tmp_path):
        from click.testing import CliRunner

        from redteam_toolkit.cli import cli

        path = tmp_path / "authorization.yml"
        path.write_text(_minimal_auth_yaml())

        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--authorization", str(path)])
        assert result.exit_code == 0
        assert "Rate budget" in result.output
        assert "default" in result.output

    def test_configured_budget_shown(self, tmp_path):
        from click.testing import CliRunner

        from redteam_toolkit.cli import cli

        path = tmp_path / "authorization.yml"
        path.write_text(_minimal_auth_yaml(extra="rate_limits:\n  max_total_requests: 2000\n  max_per_second: 50\n"))

        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--authorization", str(path)])
        assert result.exit_code == 0
        assert "2000" in result.output
        normalized = " ".join(result.output.split())  # collapse Rich's line-wrapping
        assert "configured in authorization.yml" in normalized
