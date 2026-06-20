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


class Engagement:
    def __init__(self, authorization: Authorization, audit_log_path: str | Path):
        self.authorization = authorization
        self.audit_log = AuditLog(audit_log_path)

    @classmethod
    def load(
        cls, authorization_path: str | Path, audit_log_path: str | Path | None = None
    ) -> Engagement:
        auth = load_authorization(authorization_path)
        if audit_log_path is None:
            audit_log_path = Path(authorization_path).parent / f"{auth.engagement_id}.audit.jsonl"
        return cls(auth, audit_log_path)

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
