from __future__ import annotations

import datetime
import tempfile
from pathlib import Path

import yaml

from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity


def _write_auth(path: Path) -> str:
    now = datetime.datetime.now(datetime.UTC)
    engagement_id = "build-test"
    path.write_text(yaml.safe_dump({
        "engagement_id": engagement_id,
        "authorized_by": "Jane Doe",
        "authorized_contact_email": "jane@example.com",
        "client": "Acme Corp",
        "scope": {
            "targets": ["127.0.0.1"],
            "allowed_categories": ["recon", "active"],
        },
        "window": {
            "start": (now - datetime.timedelta(hours=1)).isoformat(),
            "end": (now + datetime.timedelta(days=1)).isoformat(),
        },
        "confirmation_phrase": "confirmed",
    }))
    return engagement_id


class TestBuildReport:
    def test_builds_report_from_persisted_results(self):
        from redteam_toolkit.core.authorization import load_authorization
        from redteam_toolkit.core.history import save_module_result
        from redteam_toolkit.reports.build import build_report

        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            engagement_id = _write_auth(auth_path)
            auth = load_authorization(auth_path)

            db = str(Path(d) / "eng.db")
            mr = ModuleResult(module="port_scanner")
            mr.findings = [Finding(module="port_scanner", title="Open port 22", severity=Severity.INFO,
                                   category=FindingCategory.RECON, target="127.0.0.1")]
            save_module_result(db, engagement_id, "127.0.0.1", mr)

            log_path = Path(d) / f"{engagement_id}.audit.jsonl"
            report = build_report(auth, log_path, db)

            assert report.engagement_id == engagement_id
            assert report.client == "Acme Corp"
            assert len(report.all_findings) == 1

    def test_includes_audit_log_integrity(self):
        from redteam_toolkit.core.authorization import load_authorization
        from redteam_toolkit.core.engagement import Engagement
        from redteam_toolkit.reports.build import build_report

        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            engagement_id = _write_auth(auth_path)
            auth = load_authorization(auth_path)

            log_path = Path(d) / f"{engagement_id}.audit.jsonl"
            eng = Engagement(auth, log_path)
            eng.authorize_action("port_scanner", "127.0.0.1", "scan", category="recon")

            db = str(Path(d) / "eng.db")
            report = build_report(auth, log_path, db)

            assert report.audit_log_integrity_ok is True
            assert report.audit_log_entry_count == 1

    def test_detects_tampered_audit_log(self):
        import json as _json

        from redteam_toolkit.core.authorization import load_authorization
        from redteam_toolkit.core.engagement import Engagement
        from redteam_toolkit.reports.build import build_report

        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            engagement_id = _write_auth(auth_path)
            auth = load_authorization(auth_path)

            log_path = Path(d) / f"{engagement_id}.audit.jsonl"
            eng = Engagement(auth, log_path)
            eng.authorize_action("port_scanner", "127.0.0.1", "scan_a", category="recon")
            eng.authorize_action("port_scanner", "127.0.0.1", "scan_b", category="recon")

            lines = log_path.read_text().splitlines()
            tampered = _json.loads(lines[0])
            tampered["target"] = "tampered"
            lines[0] = _json.dumps(tampered)
            log_path.write_text("\n".join(lines) + "\n")

            db = str(Path(d) / "eng.db")
            report = build_report(auth, log_path, db)
            assert report.audit_log_integrity_ok is False

    def test_persists_snapshot_for_dashboard_reconstruction(self):
        """build_report() must leave enough behind in the DB that the
        dashboard (which has no access to authorization.yml or the audit
        log file) can reconstruct an equivalent report later."""
        from redteam_toolkit.core.authorization import load_authorization
        from redteam_toolkit.core.engagement import Engagement
        from redteam_toolkit.core.history import build_report_from_db
        from redteam_toolkit.reports.build import build_report

        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            engagement_id = _write_auth(auth_path)
            auth = load_authorization(auth_path)

            log_path = Path(d) / f"{engagement_id}.audit.jsonl"
            eng = Engagement(auth, log_path)
            eng.authorize_action("port_scanner", "127.0.0.1", "scan", category="recon")

            db = str(Path(d) / "eng.db")
            build_report(auth, log_path, db)

            reconstructed = build_report_from_db(db, engagement_id)
            assert reconstructed is not None
            assert reconstructed.client == "Acme Corp"
            assert reconstructed.audit_log_integrity_ok is True

    def test_no_module_results_yet(self):
        from redteam_toolkit.core.authorization import load_authorization
        from redteam_toolkit.reports.build import build_report

        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            engagement_id = _write_auth(auth_path)
            auth = load_authorization(auth_path)

            log_path = Path(d) / f"{engagement_id}.audit.jsonl"
            db = str(Path(d) / "eng.db")
            report = build_report(auth, log_path, db)

            assert report.all_findings == []
            assert report.audit_log_integrity_ok is True  # empty log is vacuously valid
