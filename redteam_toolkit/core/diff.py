"""
Diff — compare findings between two points in an engagement's persisted
history. Ports the pattern already proven in the secureaudit sibling
project's `secureaudit diff previous latest` (same stable-key matching
approach, same new/resolved/unchanged shape), adapted to this project's
actual schema: there's no single "scan run" row spanning every module the
way secureaudit's `runs` table works — module_runs accumulate one row per
module per CLI invocation against the same engagement_id, potentially
across many separate `recon`/`vuln-id`/`active` calls over time, and the
SAME module can be re-run multiple times as the engagement progresses.
"The state of the engagement as of run X" therefore means, for each
module that's been run by that point, its MOST RECENT invocation at or
before that point — not a union of every historical invocation of every
module, which would mean a finding that's since been fixed (the module
was re-run and no longer reports it) could never disappear from later
snapshots just because it was once recorded.

A score delta alone doesn't tell a reviewer *which* finding was introduced
or fixed — findings are matched across snapshots by a stable key
(module + slugified title + target) so that incidental differences (a scan
ordering things differently, slightly different evidence text) don't
produce false new/resolved pairs.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field

from redteam_toolkit.core.history import ensure_schema

_REGRESSION_SEVERITIES = ("CRITICAL", "HIGH")


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "unknown-finding"


def row_key(row: dict) -> str:
    """Stable key for a finding row. Mirrors secureaudit's
    plugin:slug:file approach — module:slug:target here, since target
    (not file) is this project's equivalent of "where this finding is
    about". Public (not module-private) because core/status.py needs
    the exact same identity scheme for finding-disposition tracking —
    a disposition set on a finding must follow the same logical
    identity diff already uses to match findings across re-scans, not
    a second, separately-maintained scheme that could drift from it."""
    return f"{row['module']}:{_slugify(row['title'])}:{row.get('target') or ''}"


def get_module_runs(db_path: str, engagement_id: str) -> list[dict]:
    """All module_runs rows for this engagement, most recent first."""
    conn = sqlite3.connect(db_path)
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM module_runs WHERE engagement_id = ? ORDER BY id DESC",
        (engagement_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def resolve_run_id(db_path: str, engagement_id: str, ref: str) -> int:
    """Resolve a run reference for this engagement — a numeric module_runs
    id, or the keywords 'latest'/'previous'."""
    if ref.isdigit():
        return int(ref)

    runs = get_module_runs(db_path, engagement_id)

    if ref == "latest":
        if not runs:
            raise ValueError(f"No runs found for engagement '{engagement_id}'.")
        return runs[0]["id"]

    if ref == "previous":
        if len(runs) < 2:
            raise ValueError(
                f"Not enough runs to resolve 'previous' for engagement "
                f"'{engagement_id}' (need at least 2, have {len(runs)})."
            )
        return runs[1]["id"]

    raise ValueError(f"Invalid run reference: {ref!r}. Use a run ID, 'latest', or 'previous'.")


def get_findings_as_of(db_path: str, engagement_id: str, run_id: int) -> list[dict]:
    """The state of knowledge as of run_id: for EVERY module that has been
    run for this engagement at or before run_id's own timestamp, use only
    that module's MOST RECENT invocation at or before that point — not a
    union of every historical invocation of it.

    This distinction matters and was caught by actually testing the
    "resolved" case, not assumed correct from the cumulative-union version
    written first: if module X found a problem in an early run and was
    re-run later with the problem fixed, a naive union of every run's
    findings would keep including the old (fixed) finding forever, since
    it was once recorded — meaning nothing could ever show as resolved.
    Using each module's latest-as-of-this-point run instead means a
    finding that's gone in the most recent re-run of its own module is
    correctly absent from the snapshot.
    """
    conn = sqlite3.connect(db_path)
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row

    cutoff = conn.execute(
        "SELECT timestamp FROM module_runs WHERE id = ?", (run_id,)
    ).fetchone()
    if cutoff is None:
        conn.close()
        return []
    cutoff_ts = cutoff["timestamp"]

    latest_run_ids = conn.execute(
        """
        SELECT MAX(id) AS id FROM module_runs
        WHERE engagement_id = ? AND timestamp <= ?
        GROUP BY module
        """,
        (engagement_id, cutoff_ts),
    ).fetchall()
    run_ids = [r["id"] for r in latest_run_ids]
    if not run_ids:
        conn.close()
        return []

    placeholders = ",".join("?" * len(run_ids))
    rows = conn.execute(
        f"SELECT * FROM findings WHERE run_id IN ({placeholders})", run_ids
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@dataclass
class DiffResult:
    engagement_id: str
    run1_id: int
    run2_id: int
    new: list[dict] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_new_regression(self) -> bool:
        """True if any newly-appeared finding is CRITICAL or HIGH severity
        AND is not dispositioned as false-positive/accepted-risk. Reads
        `status` via .get() with a default of "open" so this stays
        correct for any DiffResult built without ever calling
        annotate_with_status() (every existing test that constructs a
        DiffResult directly, never setting 'status' on its finding
        dicts, keeps behaving exactly as before — "open" excludes
        nothing)."""
        return any(
            f["severity"] in _REGRESSION_SEVERITIES
            and f.get("status", "open") not in ("false-positive", "accepted-risk")
            for f in self.new
        )

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "run1": self.run1_id,
            "run2": self.run2_id,
            "new": self.new,
            "resolved": self.resolved,
            "unchanged_count": self.unchanged_count,
            "regression": self.has_new_regression,
        }


def diff_runs(db_path: str, engagement_id: str, run1_id: int, run2_id: int) -> DiffResult:
    """Compare the engagement's cumulative findings as of run1 ('before')
    against as of run2 ('after'). run1 is the baseline, run2 is what's
    changed since."""
    findings1 = get_findings_as_of(db_path, engagement_id, run1_id)
    findings2 = get_findings_as_of(db_path, engagement_id, run2_id)

    keys1 = {row_key(f): f for f in findings1}
    keys2 = {row_key(f): f for f in findings2}

    new_keys = set(keys2) - set(keys1)
    resolved_keys = set(keys1) - set(keys2)
    unchanged_keys = set(keys1) & set(keys2)

    result = DiffResult(engagement_id=engagement_id, run1_id=run1_id, run2_id=run2_id)
    result.new = [keys2[k] for k in new_keys]
    result.resolved = [keys1[k] for k in resolved_keys]
    result.unchanged_count = len(unchanged_keys)
    return result
