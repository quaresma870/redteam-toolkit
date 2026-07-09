"""
Finding disposition tracking — mark a finding as a false positive, an
accepted risk, or remediated, and have that disposition persist across
future re-scans of the same engagement.

Uses the exact same stable-key scheme diff.py already established
(module + slugified title + target) rather than inventing a second
identity scheme — a finding that reappears identically on every
subsequent recon/vuln-id/active run is the same *logical* finding even
though it gets a brand new `findings.id` row every single scan, and a
disposition set once should follow that logical identity, not one
specific row.

Ported from the same problem secureaudit's core/baseline.py already
solved for its own domain (save_baseline() / apply_suppressions(), plus
inline "# secureaudit-ignore" comments) — used as a reference for the
*principle* (a disposition is recorded, shown separately, never silently
dropped from view) rather than copied verbatim, since secureaudit's
findings are per-file-and-line while this project's are per-target/
per-engagement, so inline suppression comments don't translate here.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime

from redteam_toolkit.core.diff import row_key
from redteam_toolkit.core.history import ensure_schema

STATUSES = ("open", "false-positive", "accepted-risk", "remediated")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_status (
    engagement_id TEXT NOT NULL,
    finding_key   TEXT NOT NULL,
    status        TEXT NOT NULL,
    reason        TEXT,
    set_at        TEXT NOT NULL,
    until         TEXT,
    PRIMARY KEY (engagement_id, finding_key)
);
"""


def _ensure_status_schema(conn: sqlite3.Connection) -> None:
    ensure_schema(conn)
    conn.executescript(_SCHEMA)


@dataclass
class Disposition:
    status: str
    reason: str | None
    set_at: str
    until: str | None

    @property
    def is_expired(self) -> bool:
        """True if `until` is set and is in the past. An expired
        accepted-risk disposition silently reverts to 'open' on read
        (see get_status()) rather than staying accepted-risk forever by
        default -- a temporary risk acceptance shouldn't become a
        permanent one just because nobody remembered to revisit it."""
        if not self.until:
            return False
        return date.fromisoformat(self.until) < datetime.now(UTC).date()


def set_status(
    db_path: str,
    engagement_id: str,
    finding_key: str,
    status: str,
    reason: str | None = None,
    until: str | None = None,
) -> None:
    if status not in STATUSES:
        raise ValueError(f"Invalid status {status!r}. Must be one of {STATUSES}.")
    if until is not None:
        # Validate eagerly (fails fast with a clear message) rather than
        # storing an unparseable string that only breaks later, silently,
        # inside is_expired's own date.fromisoformat() call.
        date.fromisoformat(until)

    conn = sqlite3.connect(db_path)
    _ensure_status_schema(conn)
    conn.execute(
        "INSERT INTO finding_status (engagement_id, finding_key, status, reason, set_at, until) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (engagement_id, finding_key) DO UPDATE SET "
        "status = excluded.status, reason = excluded.reason, "
        "set_at = excluded.set_at, until = excluded.until",
        (engagement_id, finding_key, status, reason, datetime.now(UTC).isoformat(), until),
    )
    conn.commit()
    conn.close()


def get_status(db_path: str, engagement_id: str, finding_key: str) -> Disposition | None:
    """Returns the current disposition, or None if never set OR if an
    accepted-risk/false-positive disposition has expired (see
    Disposition.is_expired) -- None means "treat as open", the same
    meaning as a finding that was never triaged at all."""
    conn = sqlite3.connect(db_path)
    _ensure_status_schema(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT status, reason, set_at, until FROM finding_status "
        "WHERE engagement_id = ? AND finding_key = ?",
        (engagement_id, finding_key),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    disposition = Disposition(**dict(row))
    if disposition.is_expired:
        return None
    return disposition


def find_finding_by_id(db_path: str, finding_id: int) -> dict | None:
    """Resolves a real `findings.id` primary key (the id a person would
    see in a report, `diff --json`, or the dashboard) to its full row
    plus the engagement_id it belongs to (via module_runs) -- the
    lookup the `triage` CLI command uses so a person can act on a
    specific finding they're looking at without needing to type out
    the module:slug:target key by hand."""
    conn = sqlite3.connect(db_path)
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT findings.*, module_runs.engagement_id AS engagement_id
        FROM findings JOIN module_runs ON findings.run_id = module_runs.id
        WHERE findings.id = ?
        """,
        (finding_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def annotate_with_status(rows: list[dict], db_path: str, engagement_id: str) -> None:
    """Mutates each row dict in place, adding row['status'] (defaulting
    to 'open') and row['status_reason'] (if a reason was recorded) --
    used by both `diff` and `report` so a dispositioned finding is
    visually distinct rather than looking identical to a never-triaged
    one. Never removes a row from the list — a disposition changes how
    a finding is DISPLAYED, never whether it's shown at all."""
    for row in rows:
        key = row_key(row)
        disposition = get_status(db_path, engagement_id, key)
        row["status"] = disposition.status if disposition else "open"
        if disposition and disposition.reason:
            row["status_reason"] = disposition.reason
