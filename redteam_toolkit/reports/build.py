"""
Builds a full EngagementReport from a validated Authorization, its audit
log, and the persisted module results for that engagement — the single
function every report format (HTML, PDF) and the dashboard render from.
"""

from __future__ import annotations

from pathlib import Path

from redteam_toolkit.core.audit_log import verify_log_integrity
from redteam_toolkit.core.authorization import Authorization
from redteam_toolkit.core.cvss import ensure_all_scored
from redteam_toolkit.core.history import load_module_results
from redteam_toolkit.core.models import EngagementReport


def build_report(
    authorization: Authorization, audit_log_path: str | Path, db_path: str | Path
) -> EngagementReport:
    from redteam_toolkit.core.history import register_engagement

    module_results = load_module_results(db_path, authorization.engagement_id)
    for mr in module_results:
        ensure_all_scored(mr.findings)

    log_path = Path(audit_log_path)
    integrity_ok, _, entry_count = verify_log_integrity(log_path)

    # Persist a snapshot so the dashboard (which has no access to the
    # original authorization.yml or audit log file) can reconstruct an
    # equivalent report later from the database alone.
    register_engagement(
        db_path,
        engagement_id=authorization.engagement_id,
        client=authorization.client,
        authorized_by=authorization.authorized_by,
        target_scope=authorization.scope.targets,
        window_start=authorization.window.start.isoformat(),
        window_end=authorization.window.end.isoformat(),
        audit_log_integrity_ok=integrity_ok,
        audit_log_entry_count=entry_count,
    )

    return EngagementReport(
        engagement_id=authorization.engagement_id,
        target_scope=authorization.scope.targets,
        authorized_by=authorization.authorized_by,
        client=authorization.client,
        window_start=authorization.window.start.isoformat(),
        window_end=authorization.window.end.isoformat(),
        module_results=module_results,
        audit_log_integrity_ok=integrity_ok,
        audit_log_entry_count=entry_count,
    )
