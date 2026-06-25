"""
Authorization & scope — the single most important file in this toolkit.

Nothing in redteam-toolkit runs against any target without a validated
authorization.yml. This module parses, validates, and answers the only
question that matters before any module touches a network: is this target,
at this moment, for this category of test, actually authorized?
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


class AuthorizationError(ValueError):
    """Raised when authorization.yml is missing, malformed, or invalid."""


@dataclass
class Scope:
    targets: list[str]
    excluded_targets: list[str] = field(default_factory=list)
    allowed_categories: list[str] = field(default_factory=list)


@dataclass
class Window:
    start: datetime
    end: datetime


@dataclass
class RateLimits:
    """Optional override of the global rate budget defaults. Configured
    under authorization.yml's 'rate_limits' key — absent means the
    defaults in core/rate_limit.py apply."""
    max_total_requests: int
    max_per_second: float


@dataclass
class SessionAuth:
    """Session credentials (a cookie, a bearer token, or any other
    header-based auth) to attach to every outgoing HTTP request a module
    makes, for scanning targets behind a login wall. Configured under
    authorization.yml's optional 'session_auth.headers' key, and/or
    supplied per-invocation via --session-header.

    These are credentials — treated with the same care as everything
    else security-sensitive in this toolkit. repr()/str() are
    deliberately overridden to redact header values, so an accidental
    print(), f-string, or log call anywhere in the codebase (now or
    added later) can't leak a live session token in plaintext by
    mistake. The audit log and every report-rendering path are never
    given this object at all, by construction — there's nothing for
    them to accidentally serialise."""
    headers: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        redacted = {k: "***REDACTED***" for k in self.headers}
        return f"SessionAuth(headers={redacted!r})"

    __str__ = __repr__


@dataclass
class Authorization:
    engagement_id: str
    authorized_by: str
    authorized_contact_email: str
    client: str
    scope: Scope
    window: Window
    confirmation_phrase: str
    rate_limits: RateLimits | None = None
    session_auth: SessionAuth | None = None
    source_path: Path | None = None

    def is_within_window(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return self.window.start <= now <= self.window.end

    def is_in_scope(self, target: str) -> bool:
        """CIDR/IP and wildcard-domain matching. Exclusions always win,
        even if a target also matches an inclusion pattern."""
        for excl in self.scope.excluded_targets:
            if _matches(target, excl):
                return False
        return any(_matches(target, inc) for inc in self.scope.targets)

    def allows_category(self, category: str) -> bool:
        return category in self.scope.allowed_categories


def _matches(target: str, pattern: str) -> bool:
    """Match a target string against a scope pattern: CIDR/IP network first,
    then wildcard domain ('*.example.com'), then exact string match."""
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            pass  # target isn't an IP — fall through to domain matching
    except ValueError:
        pass  # pattern isn't a CIDR/IP — fall through to domain matching

    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        bare = pattern[2:]    # "example.com"
        return target == bare or target.endswith(suffix)

    return target == pattern


_REQUIRED_FIELDS = (
    "engagement_id", "authorized_by", "authorized_contact_email",
    "client", "scope", "window", "confirmation_phrase",
)


def load_authorization(path: str | Path) -> Authorization:
    """Parse and fully validate an authorization.yml. Raises AuthorizationError
    with a specific, actionable message on any problem — never silently
    accepts a partially-valid file."""
    path = Path(path)
    if not path.exists():
        raise AuthorizationError(f"Authorization file not found: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"Authorization file is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise AuthorizationError("Authorization file must be a YAML mapping at the top level.")

    missing = [f for f in _REQUIRED_FIELDS if not data.get(f)]
    if missing:
        raise AuthorizationError(
            f"Authorization file is missing or has an empty required field: {', '.join(missing)}"
        )

    scope_data = data["scope"]
    if not isinstance(scope_data, dict) or not scope_data.get("targets"):
        raise AuthorizationError(
            "'scope.targets' must be a non-empty list — define at least one authorized target."
        )

    window_data = data["window"]
    if not isinstance(window_data, dict) or not window_data.get("start") or not window_data.get("end"):
        raise AuthorizationError("'window' must include both a non-empty 'start' and 'end' timestamp.")

    try:
        start = _parse_datetime(window_data["start"])
        end = _parse_datetime(window_data["end"])
    except (ValueError, TypeError) as exc:
        raise AuthorizationError(f"'window' timestamps must be ISO 8601: {exc}") from exc

    if end <= start:
        raise AuthorizationError("'window.end' must be after 'window.start'.")

    scope = Scope(
        targets=list(scope_data["targets"]),
        excluded_targets=list(scope_data.get("excluded_targets") or []),
        allowed_categories=list(scope_data.get("allowed_categories") or []),
    )

    rate_limits = None
    rate_data = data.get("rate_limits")
    if rate_data:
        if not isinstance(rate_data, dict):
            raise AuthorizationError("'rate_limits' must be a mapping with 'max_total_requests'/'max_per_second'.")
        try:
            rate_limits = RateLimits(
                max_total_requests=int(rate_data["max_total_requests"]),
                max_per_second=float(rate_data["max_per_second"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationError(
                f"'rate_limits' must include numeric 'max_total_requests' and 'max_per_second': {exc}"
            ) from exc

    session_auth = None
    session_auth_data = data.get("session_auth")
    if session_auth_data:
        if not isinstance(session_auth_data, dict) or not isinstance(session_auth_data.get("headers"), dict):
            raise AuthorizationError(
                "'session_auth' must be a mapping with a 'headers' mapping of header name to value."
            )
        session_auth = SessionAuth(headers={str(k): str(v) for k, v in session_auth_data["headers"].items()})

    return Authorization(
        engagement_id=str(data["engagement_id"]),
        authorized_by=str(data["authorized_by"]),
        authorized_contact_email=str(data["authorized_contact_email"]),
        client=str(data["client"]),
        scope=scope,
        window=Window(start=start, end=end),
        confirmation_phrase=str(data["confirmation_phrase"]),
        rate_limits=rate_limits,
        session_auth=session_auth,
        source_path=path,
    )


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt
