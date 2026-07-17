"""
Engagement — ties together a validated Authorization and the tamper-evident
audit log, and is the structural gate every module's network/file access
must pass through.

This is deliberately not a convention modules are expected to follow on
their own — the gate lives here, once, and every module calls through it
before touching a target. A module that bypasses this entirely is a bug to
fix in that module, not a gap in the gate itself.
"""

from __future__ import annotations

from pathlib import Path

from redteam_toolkit.core.audit_log import AuditLog
from redteam_toolkit.core.authorization import Authorization, load_authorization


class ScopeViolation(PermissionError):
    """Raised when a module attempts an action outside the validated
    scope, time window, or allowed categories. Always logged before raising."""


class ActiveTierNotConfirmed(ScopeViolation):
    """Raised when an active-tier module is invoked without the in-the-moment
    engagement-ID confirmation, even if 'active' is an authorized category.
    Being in scope for the category is not the same as having confirmed
    intent to run this specific, higher-risk tier right now."""


class Engagement:
    def __init__(
        self,
        authorization: Authorization,
        audit_log_path: str | Path,
        extra_session_headers: dict[str, str] | None = None,
        insecure: bool = False,
    ):
        self.authorization = authorization
        self.audit_log = AuditLog(audit_log_path)
        # Active-tier modules require an additional, in-the-moment
        # confirmation on top of 'active' being in allowed_categories —
        # see confirm_active_tier(). Resets every process; never persisted.
        self._active_tier_confirmed = False
        # CLI --session-header values take precedence over authorization.yml's
        # session_auth.headers on a per-header-name basis (a fresher,
        # more explicit, per-invocation override), not an all-or-nothing
        # replacement — supplying one extra header via the CLI doesn't
        # drop whatever's already configured in the file.
        self._extra_session_headers = dict(extra_session_headers or {})
        # --insecure is deliberately CLI-only, with no authorization.yml
        # equivalent — unlike session_auth, this disables a real security
        # protection (TLS certificate verification), and a config-file
        # default would risk silently carrying over to a future
        # engagement against a target that DOES have a valid cert, where
        # it's no longer appropriate. Requiring it fresh on every
        # invocation (like curl's own -k/--insecure) matches how
        # security-relevant, non-persistent choices should work.
        self._insecure = insecure

        from redteam_toolkit.core.rate_limit import (
            DEFAULT_MAX_PER_SECOND,
            DEFAULT_MAX_TOTAL_REQUESTS,
            GlobalRateBudget,
        )

        rl = authorization.rate_limits
        self.rate_budget = GlobalRateBudget(
            max_total_requests=rl.max_total_requests if rl else DEFAULT_MAX_TOTAL_REQUESTS,
            max_per_second=rl.max_per_second if rl else DEFAULT_MAX_PER_SECOND,
        )

    def auth_headers(self) -> dict[str, str]:
        """Headers every module's HTTP-based fetch should attach to
        outgoing requests, for scanning targets behind a login wall —
        authorization.yml's session_auth.headers merged with any
        --session-header CLI overrides (CLI wins per-header-name on
        conflict). Empty dict (the default) means no session auth is
        configured at all, identical to today's unauthenticated-only
        behaviour for every existing engagement that doesn't use this."""
        headers = dict(self.authorization.session_auth.headers) if self.authorization.session_auth else {}
        headers.update(self._extra_session_headers)
        return headers

    def ssl_context(self):
        """Returns None (default: real certificate verification, via
        Python's own default SSLContext) unless --insecure was passed,
        in which case returns an SSLContext with verification disabled
        — for scanning internal/staging targets with a self-signed or
        otherwise unverifiable certificate, an extremely common
        situation for exactly the kind of authorized internal
        engagements this tool exists for. Confirmed this was a real,
        not hypothetical, gap: every HTTP-based module failed silently
        (a single unhelpful INFO finding, not a crash, but also no
        actual scan) against a real self-signed-cert HTTPS target
        before this existed, reproduced directly against a real TLS
        server before deciding this was worth building."""
        if not self._insecure:
            return None
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @classmethod
    def load(
        cls,
        authorization_path: str | Path,
        audit_log_path: str | Path | None = None,
        extra_session_headers: dict[str, str] | None = None,
        insecure: bool = False,
    ) -> Engagement:
        auth = load_authorization(authorization_path)
        if audit_log_path is None:
            audit_log_path = Path(authorization_path).parent / f"{auth.engagement_id}.audit.jsonl"
        return cls(auth, audit_log_path, extra_session_headers=extra_session_headers, insecure=insecure)

    def confirm_active_tier(self, typed_engagement_id: str) -> None:
        """Required once per session before any active-tier module can run.
        Deliberately takes the literal engagement ID as a typed argument,
        not a boolean flag — this can't be scripted around with a single
        switch the way --yes-i-am-sure could be copy-pasted into a script
        without ever being read.
        """
        if "active" not in self.authorization.scope.allowed_categories:
            self.audit_log.record(
                engagement_id=self.authorization.engagement_id,
                module="engagement",
                target="-",
                action="active_tier_confirmation",
                allowed=False,
                detail={"reason": "'active' is not in this authorization's allowed_categories"},
            )
            raise ActiveTierNotConfirmed(
                "Refused: 'active' is not in this authorization's allowed_categories."
            )

        if typed_engagement_id != self.authorization.engagement_id:
            self.audit_log.record(
                engagement_id=self.authorization.engagement_id,
                module="engagement",
                target="-",
                action="active_tier_confirmation",
                allowed=False,
                detail={"reason": "typed engagement ID did not match"},
            )
            raise ActiveTierNotConfirmed(
                "Refused: typed engagement ID does not match this authorization. "
                "Active-tier modules remain unconfirmed."
            )

        self._active_tier_confirmed = True
        self.audit_log.record(
            engagement_id=self.authorization.engagement_id,
            module="engagement",
            target="-",
            action="active_tier_confirmation",
            allowed=True,
            detail={},
        )

    def authorize_action(
        self, module: str, target: str, action: str, category: str | None = None
    ) -> None:
        """The gate. Every module must call this before touching the network
        or a target's filesystem. Logs the attempt — allowed or refused —
        with equal visibility, then raises ScopeViolation if not allowed.
        Re-validates scope and window on every single call, not just once
        at startup, since an engagement's window can expire mid-run.
        """
        allowed = True
        reason = ""

        if not self.authorization.is_within_window():
            allowed = False
            reason = "outside authorized time window"
        elif not self.authorization.is_in_scope(target):
            allowed = False
            reason = "target not in authorized scope"
        elif category and not self.authorization.allows_category(category):
            allowed = False
            reason = f"category '{category}' not in allowed_categories"
        elif category == "active" and not self._active_tier_confirmed:
            allowed = False
            reason = "active-tier not confirmed for this session — call confirm_active_tier() first"

        detail = {"category": category} if allowed else {"category": category, "reason": reason}
        self.audit_log.record(
            engagement_id=self.authorization.engagement_id,
            module=module,
            target=target,
            action=action,
            allowed=allowed,
            detail=detail,
        )

        if not allowed:
            raise ScopeViolation(f"Refused: {action} against {target} — {reason}")
