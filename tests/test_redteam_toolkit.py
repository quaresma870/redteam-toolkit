"""
Tests for redteam-toolkit Sprint 0 — authorization, audit log, engagement
gate, data models, and CLI.
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from redteam_toolkit.core.audit_log import AuditLog, verify_log_integrity
from redteam_toolkit.core.authorization import (
    Authorization,
    AuthorizationError,
    Scope,
    Window,
    load_authorization,
)
from redteam_toolkit.core.engagement import Engagement, ScopeViolation
from redteam_toolkit.core.models import (
    EngagementReport,
    Finding,
    FindingCategory,
    ModuleResult,
    Severity,
)


def _write_auth_yaml(path: Path, **overrides) -> None:
    now = datetime.now(UTC)
    defaults = {
        "engagement_id": "test-2026-q1",
        "authorized_by": "Jane Doe, CISO",
        "authorized_contact_email": "jane@example.com",
        "client": "Example Corp",
        "scope": {
            "targets": ["198.51.100.0/24", "*.staging.example.com"],
            "excluded_targets": ["prod.example.com"],
            "allowed_categories": ["recon", "vuln-id"],
        },
        "window": {
            "start": (now - timedelta(hours=1)).isoformat(),
            "end": (now + timedelta(days=7)).isoformat(),
        },
        "confirmation_phrase": "I confirm authorization for test-2026-q1",
    }
    defaults.update(overrides)

    import yaml
    path.write_text(yaml.safe_dump(defaults), encoding="utf-8")


# ── Authorization parsing ────────────────────────────────────────────────────

class TestLoadAuthorization:
    def test_loads_valid_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path)
            auth = load_authorization(path)
            assert auth.engagement_id == "test-2026-q1"
            assert auth.client == "Example Corp"

    def test_missing_file_raises(self):
        with pytest.raises(AuthorizationError, match="not found"):
            load_authorization("/nonexistent/authorization.yml")

    def test_invalid_yaml_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            path.write_text("not: valid: yaml: [[[")
            with pytest.raises(AuthorizationError):
                load_authorization(path)

    def test_non_mapping_top_level_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            path.write_text("- just\n- a\n- list\n")
            with pytest.raises(AuthorizationError, match="mapping"):
                load_authorization(path)

    @pytest.mark.parametrize("missing_field", [
        "engagement_id", "authorized_by", "authorized_contact_email",
        "client", "confirmation_phrase",
    ])
    def test_missing_required_field_raises(self, missing_field):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, **{missing_field: ""})
            with pytest.raises(AuthorizationError, match=missing_field):
                load_authorization(path)

    def test_empty_targets_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={"targets": [], "allowed_categories": []})
            with pytest.raises(AuthorizationError, match="targets"):
                load_authorization(path)

    def test_missing_window_start_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, window={"end": "2026-01-01T00:00:00Z"})
            with pytest.raises(AuthorizationError, match="window"):
                load_authorization(path)

    def test_end_before_start_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, window={
                "start": "2026-07-14T00:00:00Z",
                "end": "2026-07-01T00:00:00Z",
            })
            with pytest.raises(AuthorizationError, match="after"):
                load_authorization(path)

    def test_invalid_timestamp_format_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, window={"start": "not-a-date", "end": "2026-07-01T00:00:00Z"})
            with pytest.raises(AuthorizationError, match="ISO 8601"):
                load_authorization(path)

    def test_z_suffix_timestamp_parses(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, window={
                "start": "2020-01-01T00:00:00Z",
                "end": "2099-01-01T00:00:00Z",
            })
            auth = load_authorization(path)
            assert auth.window.start.tzinfo is not None


# ── Scope matching ────────────────────────────────────────────────────────────

class TestScopeMatching:
    def _auth(self, **overrides) -> Authorization:
        now = datetime.now(UTC)
        scope = Scope(
            targets=overrides.get("targets", ["198.51.100.0/24", "*.staging.example.com", "exact-host.com"]),
            excluded_targets=overrides.get("excluded_targets", ["prod.example.com"]),
            allowed_categories=overrides.get("allowed_categories", ["recon"]),
        )
        window = Window(start=now - timedelta(hours=1), end=now + timedelta(days=1))
        return Authorization(
            engagement_id="t", authorized_by="x", authorized_contact_email="x@x.com",
            client="x", scope=scope, window=window, confirmation_phrase="x",
        )

    def test_ip_in_cidr_range(self):
        auth = self._auth()
        assert auth.is_in_scope("198.51.100.42")

    def test_ip_outside_cidr_range(self):
        auth = self._auth()
        assert not auth.is_in_scope("203.0.113.1")

    def test_wildcard_subdomain_matches(self):
        auth = self._auth()
        assert auth.is_in_scope("foo.staging.example.com")

    def test_wildcard_bare_domain_matches(self):
        auth = self._auth()
        assert auth.is_in_scope("staging.example.com")

    def test_wildcard_does_not_match_unrelated_domain(self):
        auth = self._auth()
        assert not auth.is_in_scope("staging.evil.com")

    def test_exact_hostname_match(self):
        auth = self._auth()
        assert auth.is_in_scope("exact-host.com")

    def test_exact_hostname_no_partial_match(self):
        auth = self._auth()
        assert not auth.is_in_scope("not-exact-host.com")

    def test_exclusion_overrides_cidr_inclusion(self):
        auth = self._auth(targets=["198.51.100.0/24"], excluded_targets=["198.51.100.42"])
        assert not auth.is_in_scope("198.51.100.42")
        assert auth.is_in_scope("198.51.100.41")

    def test_exclusion_overrides_wildcard_inclusion(self):
        auth = self._auth(
            targets=["*.example.com"],
            excluded_targets=["prod.example.com"],
        )
        assert not auth.is_in_scope("prod.example.com")
        assert auth.is_in_scope("staging.example.com")

    def test_single_ip_as_target_pattern(self):
        auth = self._auth(targets=["203.0.113.5"])
        assert auth.is_in_scope("203.0.113.5")
        assert not auth.is_in_scope("203.0.113.6")

    def test_allows_category(self):
        auth = self._auth(allowed_categories=["recon", "vuln-id"])
        assert auth.allows_category("recon")
        assert auth.allows_category("vuln-id")
        assert not auth.allows_category("active")

    def test_no_categories_allows_nothing(self):
        auth = self._auth(allowed_categories=[])
        assert not auth.allows_category("recon")


# ── Time window ───────────────────────────────────────────────────────────────

class TestTimeWindow:
    def test_within_window(self):
        now = datetime.now(UTC)
        auth = Authorization(
            engagement_id="t", authorized_by="x", authorized_contact_email="x@x.com", client="x",
            scope=Scope(targets=["1.2.3.4"]),
            window=Window(start=now - timedelta(hours=1), end=now + timedelta(hours=1)),
            confirmation_phrase="x",
        )
        assert auth.is_within_window()

    def test_before_window_start(self):
        now = datetime.now(UTC)
        auth = Authorization(
            engagement_id="t", authorized_by="x", authorized_contact_email="x@x.com", client="x",
            scope=Scope(targets=["1.2.3.4"]),
            window=Window(start=now + timedelta(hours=1), end=now + timedelta(hours=2)),
            confirmation_phrase="x",
        )
        assert not auth.is_within_window()

    def test_after_window_end(self):
        now = datetime.now(UTC)
        auth = Authorization(
            engagement_id="t", authorized_by="x", authorized_contact_email="x@x.com", client="x",
            scope=Scope(targets=["1.2.3.4"]),
            window=Window(start=now - timedelta(days=2), end=now - timedelta(days=1)),
            confirmation_phrase="x",
        )
        assert not auth.is_within_window()


# ── Audit log ─────────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_record_creates_file(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = Path(d) / "test.audit.jsonl"
            log = AuditLog(log_path)
            log.record("eng-1", "recon", "1.2.3.4", "port_scan", True)
            assert log_path.exists()

    def test_entries_are_hash_chained(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = Path(d) / "test.audit.jsonl"
            log = AuditLog(log_path)
            e1 = log.record("eng-1", "recon", "1.2.3.4", "port_scan", True)
            e2 = log.record("eng-1", "recon", "1.2.3.4", "fingerprint", True)
            assert e2.prev_hash == e1.entry_hash
            assert e1.prev_hash == "0" * 64

    def test_read_all_returns_all_entries(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = Path(d) / "test.audit.jsonl"
            log = AuditLog(log_path)
            log.record("eng-1", "recon", "1.2.3.4", "a", True)
            log.record("eng-1", "recon", "1.2.3.4", "b", True)
            log.record("eng-1", "recon", "1.2.3.4", "c", False, {"reason": "out of scope"})
            entries = log.read_all()
            assert len(entries) == 3
            assert entries[2]["allowed"] is False

    def test_read_all_empty_when_no_log(self):
        with tempfile.TemporaryDirectory() as d:
            assert AuditLog(Path(d) / "nope.jsonl").read_all() == []

    def test_log_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = Path(d) / "test.audit.jsonl"
            AuditLog(log_path).record("eng-1", "recon", "1.2.3.4", "a", True)
            log2 = AuditLog(log_path)
            log2.record("eng-1", "recon", "1.2.3.4", "b", True)
            entries = log2.read_all()
            assert len(entries) == 2
            assert entries[1]["prev_hash"] == entries[0]["entry_hash"]


class TestAuditLogIntegrity:
    def test_valid_log_passes(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = Path(d) / "test.audit.jsonl"
            log = AuditLog(log_path)
            log.record("eng-1", "recon", "1.2.3.4", "a", True)
            log.record("eng-1", "recon", "1.2.3.4", "b", True)
            log.record("eng-1", "recon", "1.2.3.4", "c", False)
            valid, broken_line = verify_log_integrity(log_path)
            assert valid
            assert broken_line is None

    def test_empty_log_is_valid(self):
        with tempfile.TemporaryDirectory() as d:
            valid, broken_line = verify_log_integrity(Path(d) / "nonexistent.jsonl")
            assert valid

    def test_tampered_entry_detected(self):
        """The core safety property: editing a historical entry must be detectable."""
        with tempfile.TemporaryDirectory() as d:
            log_path = Path(d) / "test.audit.jsonl"
            log = AuditLog(log_path)
            log.record("eng-1", "recon", "1.2.3.4", "a", True)
            log.record("eng-1", "recon", "1.2.3.4", "b", True)
            log.record("eng-1", "recon", "1.2.3.4", "c", True)

            lines = log_path.read_text().splitlines()
            tampered = json.loads(lines[1])
            tampered["target"] = "9.9.9.9"  # change content without recomputing the hash
            lines[1] = json.dumps(tampered)
            log_path.write_text("\n".join(lines) + "\n")

            valid, broken_line = verify_log_integrity(log_path)
            assert not valid
            assert broken_line == 2

    def test_deleted_entry_detected(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = Path(d) / "test.audit.jsonl"
            log = AuditLog(log_path)
            log.record("eng-1", "recon", "1.2.3.4", "a", True)
            log.record("eng-1", "recon", "1.2.3.4", "b", True)
            log.record("eng-1", "recon", "1.2.3.4", "c", True)

            lines = log_path.read_text().splitlines()
            del lines[1]  # remove the middle entry
            log_path.write_text("\n".join(lines) + "\n")

            valid, broken_line = verify_log_integrity(log_path)
            assert not valid

    def test_reordered_entries_detected(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = Path(d) / "test.audit.jsonl"
            log = AuditLog(log_path)
            log.record("eng-1", "recon", "1.2.3.4", "a", True)
            log.record("eng-1", "recon", "1.2.3.4", "b", True)
            log.record("eng-1", "recon", "1.2.3.4", "c", True)

            lines = log_path.read_text().splitlines()
            lines[1], lines[2] = lines[2], lines[1]
            log_path.write_text("\n".join(lines) + "\n")

            valid, broken_line = verify_log_integrity(log_path)
            assert not valid


# ── Engagement gate ───────────────────────────────────────────────────────────

class TestEngagementGate:
    def _engagement(self, tmpdir, **auth_overrides) -> Engagement:
        path = Path(tmpdir) / "authorization.yml"
        _write_auth_yaml(path, **auth_overrides)
        log_path = Path(tmpdir) / "test.audit.jsonl"
        return Engagement.load(path, log_path)

    def test_in_scope_action_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._engagement(d)
            eng.authorize_action("recon", "198.51.100.5", "port_scan", category="recon")
            entries = eng.audit_log.read_all()
            assert entries[-1]["allowed"] is True

    def test_out_of_scope_target_refused(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._engagement(d)
            with pytest.raises(ScopeViolation, match="not in authorized scope"):
                eng.authorize_action("recon", "203.0.113.1", "port_scan", category="recon")

    def test_out_of_scope_refusal_is_logged(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._engagement(d)
            with pytest.raises(ScopeViolation):
                eng.authorize_action("recon", "203.0.113.1", "port_scan", category="recon")
            entries = eng.audit_log.read_all()
            assert entries[-1]["allowed"] is False
            assert "scope" in entries[-1]["detail"]["reason"]

    def test_disallowed_category_refused(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._engagement(d, scope={
                "targets": ["198.51.100.0/24"], "allowed_categories": ["recon"],
            })
            with pytest.raises(ScopeViolation, match="category"):
                eng.authorize_action("sqli", "198.51.100.5", "probe", category="active")

    def test_excluded_target_refused_even_if_in_cidr(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._engagement(d, scope={
                "targets": ["198.51.100.0/24"],
                "excluded_targets": ["198.51.100.99"],
                "allowed_categories": ["recon"],
            })
            with pytest.raises(ScopeViolation):
                eng.authorize_action("recon", "198.51.100.99", "port_scan", category="recon")

    def test_expired_window_refused(self):
        with tempfile.TemporaryDirectory() as d:
            now = datetime.now(UTC)
            eng = self._engagement(d, window={
                "start": (now - timedelta(days=10)).isoformat(),
                "end": (now - timedelta(days=1)).isoformat(),
            })
            with pytest.raises(ScopeViolation, match="window"):
                eng.authorize_action("recon", "198.51.100.5", "port_scan", category="recon")

    def test_no_category_specified_skips_category_check(self):
        """A module that doesn't pass a category (e.g. a generic action) isn't
        blocked by the category gate — only scope and window apply."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._engagement(d, scope={"targets": ["198.51.100.0/24"], "allowed_categories": []})
            eng.authorize_action("generic", "198.51.100.5", "ping")  # no category kwarg
            entries = eng.audit_log.read_all()
            assert entries[-1]["allowed"] is True

    def test_every_call_revalidates_not_just_first(self):
        """Re-validates on every call — simulates a window expiring mid-run."""
        with tempfile.TemporaryDirectory() as d:
            now = datetime.now(UTC)
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, window={
                "start": (now - timedelta(hours=1)).isoformat(),
                "end": (now + timedelta(seconds=1)).isoformat(),
            })
            eng = Engagement.load(path, Path(d) / "test.audit.jsonl")
            eng.authorize_action("recon", "198.51.100.5", "first_call", category="recon")

            import time
            time.sleep(1.5)

            with pytest.raises(ScopeViolation, match="window"):
                eng.authorize_action("recon", "198.51.100.5", "second_call", category="recon")

    def test_engagement_load_default_audit_log_path(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path)
            eng = Engagement.load(path)
            assert eng.audit_log.path.name == "test-2026-q1.audit.jsonl"


# ── Data models ───────────────────────────────────────────────────────────────

class TestModels:
    def test_finding_to_dict(self):
        f = Finding(
            module="port_scanner", title="Open port 22", severity=Severity.INFO,
            category=FindingCategory.RECON, target="198.51.100.5",
            description="SSH port open",
        )
        d = f.to_dict()
        assert d["severity"] == "INFO"
        assert d["category"] == "recon"

    def test_engagement_report_aggregates_findings(self):
        report = EngagementReport(
            engagement_id="t", target_scope=["198.51.100.0/24"],
            authorized_by="x", client="x", window_start="2026-01-01", window_end="2026-01-07",
        )
        mr1 = ModuleResult(module="port_scanner")
        mr1.findings = [
            Finding(module="port_scanner", title="a", severity=Severity.HIGH,
                   category=FindingCategory.RECON, target="1.2.3.4"),
        ]
        mr2 = ModuleResult(module="fingerprint")
        mr2.findings = [
            Finding(module="fingerprint", title="b", severity=Severity.LOW,
                   category=FindingCategory.RECON, target="1.2.3.4"),
        ]
        report.module_results = [mr1, mr2]

        assert len(report.all_findings) == 2
        counts = report.counts_by_severity()
        assert counts["HIGH"] == 1
        assert counts["LOW"] == 1
        assert counts["CRITICAL"] == 0

    def test_engagement_report_to_dict(self):
        report = EngagementReport(
            engagement_id="t", target_scope=["1.2.3.4"], authorized_by="x",
            client="x", window_start="2026-01-01", window_end="2026-01-07",
            audit_log_integrity_ok=True, audit_log_entry_count=5,
        )
        d = report.to_dict()
        assert d["engagement_id"] == "t"
        assert d["audit_log"]["integrity_ok"] is True
        assert d["audit_log"]["entry_count"] == 5


# ── Mock target harness ───────────────────────────────────────────────────────

class TestMockTargetHarness:
    def test_starts_and_responds(self):
        import urllib.request

        from tests.fixtures.mock_target.server import start_mock_target

        server, port = start_mock_target()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                assert resp.status == 200
        finally:
            server.shutdown()

    def test_vulnerable_reflect_is_unescaped(self):
        import urllib.request

        from tests.fixtures.mock_target.server import start_mock_target

        server, port = start_mock_target()
        try:
            url = f"http://127.0.0.1:{port}/vulnerable/reflect?q=<script>x</script>"
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode()
            assert "<script>x</script>" in body
        finally:
            server.shutdown()

    def test_safe_reflect_is_escaped(self):
        import urllib.request

        from tests.fixtures.mock_target.server import start_mock_target

        server, port = start_mock_target()
        try:
            url = f"http://127.0.0.1:{port}/safe/reflect?q=<script>x</script>"
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode()
            assert "<script>" not in body
            assert "&lt;script&gt;" in body
        finally:
            server.shutdown()

    def test_vulnerable_redirect_follows_arbitrary_target(self):
        import http.client

        from tests.fixtures.mock_target.server import start_mock_target

        server, port = start_mock_target()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/vulnerable/redirect?next=https://evil.example.com")
            resp = conn.getresponse()
            assert resp.status == 302
            assert resp.getheader("Location") == "https://evil.example.com"
            conn.close()
        finally:
            server.shutdown()

    def test_safe_redirect_only_goes_to_fixed_path(self):
        import http.client

        from tests.fixtures.mock_target.server import start_mock_target

        server, port = start_mock_target()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/safe/redirect?next=https://evil.example.com")
            resp = conn.getresponse()
            assert resp.status == 302
            assert resp.getheader("Location") == "/"
            conn.close()
        finally:
            server.shutdown()

    def test_shutdown_stops_server(self):
        import urllib.error
        import urllib.request

        from tests.fixtures.mock_target.server import start_mock_target

        server, port = start_mock_target()
        server.shutdown()
        server.server_close()
        with pytest.raises((urllib.error.URLError, ConnectionRefusedError, OSError)):
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)


# ── CLI ───────────────────────────────────────────────────────────────────────

class TestCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_init_creates_template(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "authorization.yml"
            result = runner.invoke(cli, ["init", "--output", str(out)])
            assert result.exit_code == 0
            assert out.exists()

    def test_init_template_is_not_itself_valid(self):
        """The template must require manual completion — it must NOT pass
        validate-scope as-is, otherwise 'init' would be silently authorizing
        something nobody actually reviewed."""
        from redteam_toolkit.cli import cli
        from redteam_toolkit.core.authorization import AuthorizationError, load_authorization
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "authorization.yml"
            runner.invoke(cli, ["init", "--output", str(out)])
            with pytest.raises(AuthorizationError):
                load_authorization(out)

    def test_init_refuses_overwrite_without_force(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "authorization.yml"
            out.write_text("existing content\n")
            result = runner.invoke(cli, ["init", "--output", str(out)])
            assert result.exit_code != 0

    def test_init_force_overwrites(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "authorization.yml"
            out.write_text("existing content\n")
            result = runner.invoke(cli, ["init", "--output", str(out), "--force"])
            assert result.exit_code == 0

    def test_validate_scope_valid_file(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path)
            result = runner.invoke(cli, ["validate-scope", "--authorization", str(path)])
            assert result.exit_code == 0
            assert "valid" in result.output.lower()

    def test_validate_scope_invalid_file(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            path.write_text("engagement_id: only-this-field\n")
            result = runner.invoke(cli, ["validate-scope", "--authorization", str(path)])
            assert result.exit_code != 0

    def test_status_shows_active_engagement(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path)
            result = runner.invoke(cli, ["status", "--authorization", str(path)])
            assert result.exit_code == 0
            assert "ACTIVE" in result.output

    def test_status_shows_expired_engagement(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            now = datetime.now(UTC)
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, window={
                "start": (now - timedelta(days=10)).isoformat(),
                "end": (now - timedelta(days=1)).isoformat(),
            })
            result = runner.invoke(cli, ["status", "--authorization", str(path)])
            assert result.exit_code == 0
            assert "EXPIRED" in result.output

    def test_status_shows_audit_log_integrity(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path)

            eng = Engagement.load(path)
            eng.authorize_action("recon", "198.51.100.5", "test_action", category="recon")

            result = runner.invoke(cli, ["status", "--authorization", str(path)])
            assert result.exit_code == 0
            assert "OK" in result.output

    def test_version_flag(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0


class TestResolveTargets:
    """_resolve_targets is shared by recon/vuln-id/active — tested directly
    here so all three commands' batch behavior stays consistent without
    needing three near-identical copies of the same test."""

    def test_targets_from_argument_only(self):
        from redteam_toolkit.cli import _resolve_targets
        assert _resolve_targets(("a.example.com", "b.example.com"), None) == [
            "a.example.com", "b.example.com",
        ]

    def test_targets_from_file_only(self, tmp_path):
        from redteam_toolkit.cli import _resolve_targets
        f = tmp_path / "targets.txt"
        f.write_text("a.example.com\nb.example.com\n")
        assert _resolve_targets((), str(f)) == ["a.example.com", "b.example.com"]

    def test_file_ignores_blank_lines_and_comments(self, tmp_path):
        from redteam_toolkit.cli import _resolve_targets
        f = tmp_path / "targets.txt"
        f.write_text("# a comment\na.example.com\n\n   \nb.example.com\n# another\n")
        assert _resolve_targets((), str(f)) == ["a.example.com", "b.example.com"]

    def test_combines_argument_and_file(self, tmp_path):
        from redteam_toolkit.cli import _resolve_targets
        f = tmp_path / "targets.txt"
        f.write_text("b.example.com\nc.example.com\n")
        assert _resolve_targets(("a.example.com",), str(f)) == [
            "a.example.com", "b.example.com", "c.example.com",
        ]

    def test_deduplicates_preserving_first_seen_order(self, tmp_path):
        from redteam_toolkit.cli import _resolve_targets
        f = tmp_path / "targets.txt"
        f.write_text("a.example.com\nb.example.com\n")
        result = _resolve_targets(("b.example.com", "a.example.com"), str(f))
        # b, a from the argument come first (argument order), then the
        # file's a/b are both already-seen duplicates and dropped.
        assert result == ["b.example.com", "a.example.com"]

    def test_no_targets_at_all_returns_empty(self):
        from redteam_toolkit.cli import _resolve_targets
        assert _resolve_targets((), None) == []


class TestMultiTargetCLI:
    """CLI-level multi-target orchestration for recon/vuln-id/active.
    Deliberately uses an unknown module name throughout — exercises the
    real per-target loop and target-resolution code in cli.py without
    needing real network access or live infrastructure for any actual
    scan module to run against, which would make these tests flaky in
    sandboxed/offline CI environments."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_recon_runs_each_target_in_sequence(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com", "b.staging.example.com"],
                "excluded_targets": [], "allowed_categories": ["recon"],
            })
            result = runner.invoke(cli, [
                "recon", "a.staging.example.com", "b.staging.example.com",
                "--authorization", str(path), "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output
            assert result.output.count("Unknown module: nonexistent_module") == 2
            assert "🎯 Recon: a.staging.example.com" in result.output
            assert "🎯 Recon: b.staging.example.com" in result.output
            assert "2 targets queued" in result.output

    def test_recon_targets_file(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com", "b.staging.example.com"],
                "excluded_targets": [], "allowed_categories": ["recon"],
            })
            targets_file = Path(d) / "targets.txt"
            targets_file.write_text("a.staging.example.com\nb.staging.example.com\n")

            result = runner.invoke(cli, [
                "recon", "--targets-file", str(targets_file),
                "--authorization", str(path), "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output
            assert result.output.count("Unknown module: nonexistent_module") == 2

    def test_recon_no_targets_errors_clearly(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path)
            result = runner.invoke(cli, ["recon", "--authorization", str(path)])
            assert result.exit_code != 0
            assert "no targets" in result.output.lower()

    def test_recon_single_target_unchanged_output_shape(self):
        """A single target must not show the "N targets queued"/summary
        lines at all — backward-compatible output for the overwhelmingly
        common single-target case."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com"], "excluded_targets": [],
                "allowed_categories": ["recon"],
            })
            result = runner.invoke(cli, [
                "recon", "a.staging.example.com",
                "--authorization", str(path), "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output
            assert "targets queued" not in result.output
            assert "total finding" not in result.output

    def test_vuln_id_runs_each_target_in_sequence(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com", "b.staging.example.com"],
                "excluded_targets": [], "allowed_categories": ["vuln-id"],
            })
            result = runner.invoke(cli, [
                "vuln-id", "a.staging.example.com", "b.staging.example.com",
                "--authorization", str(path), "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output
            assert result.output.count("Unknown module: nonexistent_module") == 2

    def test_active_runs_each_target_in_sequence(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com", "b.staging.example.com"],
                "excluded_targets": [], "allowed_categories": ["active"],
            })
            result = runner.invoke(cli, [
                "active", "a.staging.example.com", "b.staging.example.com",
                "--authorization", str(path),
                "--confirm", "test-2026-q1",
                "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output
            assert result.output.count("Unknown module: nonexistent_module") == 2

    def test_one_out_of_scope_target_refused_others_still_run(self):
        """A mix of in-scope and out-of-scope targets — the out-of-scope
        one is refused and logged (not silently skipped), the in-scope
        one still runs. Confirms scope checking stays genuinely per-target
        inside the loop, not just at startup."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com"], "excluded_targets": [],
                "allowed_categories": ["recon"],
            })
            result = runner.invoke(cli, [
                "recon", "a.staging.example.com", "evil-out-of-scope.com",
                "--authorization", str(path), "--modules", "passive_dns",
            ])
            assert result.exit_code == 0, result.output
            assert "evil-out-of-scope.com" in result.output
            assert "a.staging.example.com" in result.output
            # The out-of-scope target's module call shows an error, not a
            # silent skip — _save_module_result/console output reflects it.
            assert "⚠" in result.output or "error" in result.output.lower()
