"""
Engagement history — persists each module run's findings to SQLite, keyed
by engagement_id, so the `report` command can reconstruct a full
EngagementReport from everything run across a session (recon + vuln-id +
active, possibly across multiple separate CLI invocations).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    engagement_id          TEXT PRIMARY KEY,
    client                 TEXT,
    authorized_by          TEXT,
    target_scope           TEXT,
    window_start           TEXT,
    window_end             TEXT,
    audit_log_integrity_ok INTEGER,
    audit_log_entry_count  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS module_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    module        TEXT NOT NULL,
    target        TEXT NOT NULL,
    error         TEXT,
    duration_ms   REAL NOT NULL,
    timestamp     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL,
    module      TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    category    TEXT NOT NULL,
    target      TEXT NOT NULL,
    description TEXT,
    evidence    TEXT,
    remediation TEXT,
    cvss_score  REAL,
    extra       TEXT,
    FOREIGN KEY (run_id) REFERENCES module_runs(id)
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    cols = [row[1] for row in conn.execute("PRAGMA table_info(engagements)").fetchall()]
    if "audit_log_integrity_ok" not in cols:
        conn.execute("ALTER TABLE engagements ADD COLUMN audit_log_integrity_ok INTEGER")
    if "audit_log_entry_count" not in cols:
        conn.execute("ALTER TABLE engagements ADD COLUMN audit_log_entry_count INTEGER NOT NULL DEFAULT 0")


def register_engagement(
    db_path: str | Path,
    engagement_id: str,
    client: str,
    authorized_by: str,
    target_scope: list[str],
    window_start: str,
    window_end: str,
    audit_log_integrity_ok: bool | None = None,
    audit_log_entry_count: int = 0,
) -> None:
    """Upsert the engagement's metadata — called once per engagement, and
    again whenever a report is built (to refresh the persisted audit log
    integrity snapshot, since the dashboard reconstructs reports purely
    from this database without access to the original audit log file)."""
    conn = sqlite3.connect(str(db_path))
    ensure_schema(conn)
    conn.execute(
        """INSERT INTO engagements
           (engagement_id, client, authorized_by, target_scope, window_start, window_end,
            audit_log_integrity_ok, audit_log_entry_count)
           VALUES (?,?,?,?,?,?,?,?)
           ON CONFLICT(engagement_id) DO UPDATE SET
             client=excluded.client, authorized_by=excluded.authorized_by,
             target_scope=excluded.target_scope, window_start=excluded.window_start,
             window_end=excluded.window_end,
             audit_log_integrity_ok=COALESCE(excluded.audit_log_integrity_ok, engagements.audit_log_integrity_ok),
             audit_log_entry_count=CASE WHEN excluded.audit_log_entry_count > 0
                                         THEN excluded.audit_log_entry_count
                                         ELSE engagements.audit_log_entry_count END""",
        (
            engagement_id, client, authorized_by, json.dumps(target_scope), window_start, window_end,
            audit_log_integrity_ok, audit_log_entry_count,
        ),
    )
    conn.commit()
    conn.close()


def save_module_result(
    db_path: str | Path, engagement_id: str, target: str, result: ModuleResult
) -> int:
    """Persist one module run (and its findings) for an engagement. Returns the run ID."""
    conn = sqlite3.connect(str(db_path))
    ensure_schema(conn)
    cur = conn.execute(
        "INSERT INTO module_runs (engagement_id, module, target, error, duration_ms, timestamp) "
        "VALUES (?,?,?,?,?,?)",
        (
            engagement_id, result.module, target, result.error, result.duration_ms,
            datetime.now(UTC).isoformat(),
        ),
    )
    run_id = cur.lastrowid

    for f in result.findings:
        conn.execute(
            "INSERT INTO findings (run_id, module, title, severity, category, target, "
            "description, evidence, remediation, cvss_score, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id, f.module, f.title, f.severity.value, f.category.value, f.target,
                f.description, f.evidence, f.remediation, f.cvss_score, json.dumps(f.extra),
            ),
        )

    conn.commit()
    conn.close()
    return run_id


def get_engagement(db_path: str | Path, engagement_id: str) -> dict | None:
    conn = sqlite3.connect(str(db_path))
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM engagements WHERE engagement_id = ?", (engagement_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_engagements(db_path: str | Path) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM engagements ORDER BY engagement_id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def load_module_results(db_path: str | Path, engagement_id: str) -> list[ModuleResult]:
    """Reconstruct one ModuleResult per distinct module name, combining
    findings across every run of that module for this engagement."""
    conn = sqlite3.connect(str(db_path))
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row

    runs = conn.execute(
        "SELECT * FROM module_runs WHERE engagement_id = ? ORDER BY id", (engagement_id,)
    ).fetchall()

    by_module: dict[str, ModuleResult] = {}
    total_duration: dict[str, float] = {}

    for run in runs:
        module = run["module"]
        if module not in by_module:
            by_module[module] = ModuleResult(module=module)
            total_duration[module] = 0.0
        total_duration[module] += run["duration_ms"]
        if run["error"]:
            by_module[module].error = run["error"]

        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ?", (run["id"],)
        ).fetchall()
        for fr in finding_rows:
            by_module[module].findings.append(Finding(
                module=fr["module"],
                title=fr["title"],
                severity=Severity(fr["severity"]),
                category=FindingCategory(fr["category"]),
                target=fr["target"],
                description=fr["description"] or "",
                evidence=fr["evidence"] or "",
                remediation=fr["remediation"] or "",
                cvss_score=fr["cvss_score"],
                extra=json.loads(fr["extra"]) if fr["extra"] else {},
            ))

    conn.close()

    for module, mr in by_module.items():
        mr.duration_ms = total_duration[module]

    return list(by_module.values())


def build_report_from_db(db_path: str | Path, engagement_id: str):
    """Reconstructs an EngagementReport purely from this database — used by
    the dashboard, which has no access to the original authorization.yml
    or audit log files, only the persisted snapshot taken when the report
    was last built via reports.build.build_report()."""
    from redteam_toolkit.core.cvss import ensure_all_scored
    from redteam_toolkit.core.models import EngagementReport

    engagement = get_engagement(db_path, engagement_id)
    if engagement is None:
        return None

    module_results = load_module_results(db_path, engagement_id)
    for mr in module_results:
        ensure_all_scored(mr.findings)

    integrity_raw = engagement.get("audit_log_integrity_ok")
    integrity_ok = bool(integrity_raw) if integrity_raw is not None else None

    return EngagementReport(
        engagement_id=engagement_id,
        target_scope=json.loads(engagement["target_scope"]) if engagement["target_scope"] else [],
        authorized_by=engagement["authorized_by"] or "",
        client=engagement["client"] or "",
        window_start=engagement["window_start"] or "",
        window_end=engagement["window_end"] or "",
        module_results=module_results,
        audit_log_integrity_ok=integrity_ok,
        audit_log_entry_count=engagement.get("audit_log_entry_count") or 0,
    )
