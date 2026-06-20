"""
Tests for the active-tier confirmation gate — the safety-critical part of
this sprint. These negative tests matter more than the detection modules'
correctness: a future refactor that accidentally weakens either check here
should fail loudly.
"""

from __future__ import annotations

from datetime import UTC


class TestActiveTierNotInAllowedCategories:
    def test_confirm_refused_when_active_not_authorized(self, engagement_factory):
        from redteam_toolkit.core.engagement import ActiveTierNotConfirmed

        eng = engagement_factory(allowed_categories=["recon", "vuln-id"])
        import pytest
        with pytest.raises(ActiveTierNotConfirmed, match="not in this authorization"):
            eng.confirm_active_tier("test")

    def test_refusal_logged(self, engagement_factory):
        from redteam_toolkit.core.engagement import ActiveTierNotConfirmed

        eng = engagement_factory(allowed_categories=["recon"])
        import contextlib
        with contextlib.suppress(ActiveTierNotConfirmed):
            eng.confirm_active_tier("test")

        entries = eng.audit_log.read_all()
        assert entries[-1]["action"] == "active_tier_confirmation"
        assert entries[-1]["allowed"] is False

    def test_module_invocation_bypassing_confirm_still_refused(self, engagement_factory):
        """Even if a module is invoked directly, skipping the CLI's
        confirm_active_tier() call entirely, authorize_action() itself must
        still refuse — the gate doesn't rely on callers behaving nicely."""
        from redteam_toolkit.active.sqli import SQLInjectionModule

        eng = engagement_factory(allowed_categories=["recon"])
        m = SQLInjectionModule(eng, fetch_fn=lambda *a: "")
        result = m.run("127.0.0.1")
        assert result.error is not None
        assert "active-tier not confirmed" in result.error or "category" in result.error


class TestActiveTierConfirmationMismatch:
    def test_wrong_typed_id_refused(self, engagement_factory):
        from redteam_toolkit.core.engagement import ActiveTierNotConfirmed

        eng = engagement_factory(allowed_categories=["active"])
        import pytest
        with pytest.raises(ActiveTierNotConfirmed, match="does not match"):
            eng.confirm_active_tier("definitely-not-the-right-id")

    def test_wrong_id_refusal_logged(self, engagement_factory):
        from redteam_toolkit.core.engagement import ActiveTierNotConfirmed

        eng = engagement_factory(allowed_categories=["active"])
        import contextlib
        with contextlib.suppress(ActiveTierNotConfirmed):
            eng.confirm_active_tier("wrong-id")

        entries = eng.audit_log.read_all()
        assert entries[-1]["allowed"] is False
        assert "match" in entries[-1]["detail"]["reason"]

    def test_module_call_refused_when_confirmation_never_attempted(self, engagement_factory):
        """The authorization file being fully valid, with 'active' correctly
        listed, is not sufficient on its own — the in-the-moment
        confirmation must actually have been called this session."""
        from redteam_toolkit.active.xss import XSSDetectionModule

        eng = engagement_factory(allowed_categories=["active"])
        # Deliberately never call eng.confirm_active_tier()
        m = XSSDetectionModule(eng, fetch_fn=lambda *a: "")
        result = m.run("127.0.0.1")
        assert result.error is not None
        assert "active-tier not confirmed" in result.error

    def test_empty_string_confirmation_refused(self, engagement_factory):
        from redteam_toolkit.core.engagement import ActiveTierNotConfirmed

        eng = engagement_factory(allowed_categories=["active"])
        import pytest
        with pytest.raises(ActiveTierNotConfirmed):
            eng.confirm_active_tier("")


class TestActiveTierConfirmationSuccess:
    def test_correct_confirmation_allows_subsequent_actions(self, engagement_factory):
        eng = engagement_factory(allowed_categories=["active"])
        eng.confirm_active_tier("test")  # "test" matches the fixture's engagement_id
        eng.authorize_action("sqli_detection", "127.0.0.1", "probe", category="active")  # must not raise

    def test_success_logged(self, engagement_factory):
        eng = engagement_factory(allowed_categories=["active"])
        eng.confirm_active_tier("test")
        entries = eng.audit_log.read_all()
        assert entries[-1]["action"] == "active_tier_confirmation"
        assert entries[-1]["allowed"] is True

    def test_confirmation_does_not_bypass_scope_check(self, engagement_factory):
        """Confirming the active tier authorizes the *category*, not a
        blanket exemption from scope/window checks — an out-of-scope
        target must still be refused."""
        import pytest

        from redteam_toolkit.core.engagement import ScopeViolation

        eng = engagement_factory(targets=["10.0.0.0/8"], allowed_categories=["active"])
        eng.confirm_active_tier("test")
        with pytest.raises(ScopeViolation, match="scope"):
            eng.authorize_action("sqli_detection", "203.0.113.5", "probe", category="active")

    def test_confirmation_does_not_bypass_window_check(self, engagement_factory):
        from datetime import datetime, timedelta

        import pytest

        from redteam_toolkit.core.engagement import ScopeViolation

        eng = engagement_factory(allowed_categories=["active"])
        eng.confirm_active_tier("test")
        # Forge an expired window directly on the loaded authorization object
        # to simulate an engagement that expires mid-session.
        eng.authorization.window.end = datetime.now(UTC) - timedelta(seconds=1)
        with pytest.raises(ScopeViolation, match="window"):
            eng.authorize_action("sqli_detection", "127.0.0.1", "probe", category="active")

    def test_recon_and_vuln_id_categories_unaffected_by_active_confirmation_state(self, engagement_factory):
        """Confirming (or not confirming) active tier must have zero effect
        on recon/vuln-id actions — these checks are independent."""
        eng = engagement_factory(allowed_categories=["recon", "vuln-id"])
        # Never confirm active tier at all
        eng.authorize_action("port_scanner", "127.0.0.1", "scan", category="recon")  # must not raise
        eng.authorize_action("tls_analyzer", "127.0.0.1", "inspect", category="vuln-id")  # must not raise
