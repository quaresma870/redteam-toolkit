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


class TestSessionAuth:
    """authorization.yml's optional session_auth.headers — for scanning
    targets behind a login wall. Session credentials are treated with
    the same care as everything else security-sensitive in this toolkit:
    never logged or rendered in plaintext anywhere."""

    def test_no_session_auth_means_none(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path)
            auth = load_authorization(path)
            assert auth.session_auth is None

    def test_session_auth_parses_correctly(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, session_auth={"headers": {"Cookie": "session=abc123"}})
            auth = load_authorization(path)
            assert auth.session_auth.headers == {"Cookie": "session=abc123"}

    def test_session_auth_missing_headers_key_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, session_auth={"not_headers": {}})
            with pytest.raises(AuthorizationError, match="session_auth"):
                load_authorization(path)

    def test_session_auth_repr_redacts_values(self):
        from redteam_toolkit.core.authorization import SessionAuth
        auth = SessionAuth(headers={"Cookie": "session=super-secret-real-token"})
        rendered = repr(auth)
        assert "super-secret-real-token" not in rendered
        assert "REDACTED" in rendered

    def test_session_auth_str_also_redacts(self):
        from redteam_toolkit.core.authorization import SessionAuth
        auth = SessionAuth(headers={"Authorization": "Bearer super-secret-real-token"})
        rendered = str(auth)
        assert "super-secret-real-token" not in rendered

    def test_session_auth_redacted_repr_still_shows_header_names(self):
        """Header NAMES (not values) are fine to show — useful for
        debugging "is auth even configured" without exposing the
        credential itself."""
        from redteam_toolkit.core.authorization import SessionAuth
        auth = SessionAuth(headers={"Cookie": "session=secret"})
        assert "Cookie" in repr(auth)


class TestEngagementAuthHeaders:
    def test_no_session_auth_means_empty_headers(self, engagement_factory):
        eng = engagement_factory()
        assert eng.auth_headers() == {}

    def test_headers_from_authorization_yml(self, engagement_factory):
        eng = engagement_factory(session_auth_headers={"Cookie": "session=abc123"})
        assert eng.auth_headers() == {"Cookie": "session=abc123"}

    def test_cli_override_merges_with_file(self):
        """A --session-header override supplements authorization.yml's
        configured headers rather than replacing the whole set."""
        import datetime

        import yaml

        from redteam_toolkit.core.engagement import Engagement

        with tempfile.TemporaryDirectory() as d:
            now = datetime.datetime.now(datetime.UTC)
            path = Path(d) / "authorization.yml"
            path.write_text(yaml.safe_dump({
                "engagement_id": "test", "authorized_by": "Test User",
                "authorized_contact_email": "test@example.com", "client": "Test Co",
                "scope": {"targets": ["127.0.0.1"], "excluded_targets": [], "allowed_categories": ["recon"]},
                "window": {
                    "start": (now - datetime.timedelta(hours=1)).isoformat(),
                    "end": (now + datetime.timedelta(days=1)).isoformat(),
                },
                "confirmation_phrase": "I confirm",
                "session_auth": {"headers": {"Cookie": "session=from-file"}},
            }))
            eng = Engagement.load(path, extra_session_headers={"Authorization": "Bearer from-cli"})
            headers = eng.auth_headers()
            assert headers["Cookie"] == "session=from-file"
            assert headers["Authorization"] == "Bearer from-cli"

    def test_cli_override_takes_precedence_on_same_header_name(self, engagement_factory):
        import datetime

        import yaml

        from redteam_toolkit.core.engagement import Engagement

        with tempfile.TemporaryDirectory() as d:
            now = datetime.datetime.now(datetime.UTC)
            path = Path(d) / "authorization.yml"
            path.write_text(yaml.safe_dump({
                "engagement_id": "test", "authorized_by": "Test User",
                "authorized_contact_email": "test@example.com", "client": "Test Co",
                "scope": {"targets": ["127.0.0.1"], "excluded_targets": [], "allowed_categories": ["recon"]},
                "window": {
                    "start": (now - datetime.timedelta(hours=1)).isoformat(),
                    "end": (now + datetime.timedelta(days=1)).isoformat(),
                },
                "confirmation_phrase": "I confirm",
                "session_auth": {"headers": {"Cookie": "session=old-from-file"}},
            }))
            eng = Engagement.load(path, extra_session_headers={"Cookie": "session=fresh-from-cli"})
            assert eng.auth_headers()["Cookie"] == "session=fresh-from-cli"


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
            valid, broken_line, _entry_count = verify_log_integrity(log_path)
            assert valid
            assert broken_line is None

    def test_empty_log_is_valid(self):
        with tempfile.TemporaryDirectory() as d:
            valid, broken_line, _entry_count = verify_log_integrity(Path(d) / "nonexistent.jsonl")
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

            valid, broken_line, _entry_count = verify_log_integrity(log_path)
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

            valid, broken_line, _entry_count = verify_log_integrity(log_path)
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

            valid, broken_line, _entry_count = verify_log_integrity(log_path)
            assert not valid


class TestAuditLogIntegrityViaRealCLI:
    """Issue #46: verifies tamper detection through the actual `status`
    command a user would run, against a real audit log produced by a
    real engagement (recon against the mock target), manually edited
    with the same kind of operations a human investigating an incident
    would use (sed-style line edit/delete/reorder), not constructed
    tampered entries built directly via the AuditLog API. The existing
    TestAuditLogIntegrity class above already covers
    verify_log_integrity() at the function level; this covers the same
    ground end-to-end through the CLI, the level a real operator
    actually interacts with."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def _real_log(self, tmpdir) -> tuple:
        """Produces a REAL audit log via a real engagement + real
        recon invocation through the actual CLI, not a hand-built
        AuditLog. Returns (auth_path, log_path)."""
        from redteam_toolkit.cli import cli

        auth_path = Path(tmpdir) / "authorization.yml"
        _write_auth_yaml(auth_path, scope={
            "targets": ["198.51.100.5"], "excluded_targets": [],
            "allowed_categories": ["recon"],
        })
        log_path = Path(tmpdir) / "test-2026-q1.audit.jsonl"

        runner = self._runner()
        runner.invoke(cli, [
            "recon", "198.51.100.5", "--authorization", str(auth_path),
            "--audit-log", str(log_path), "--modules", "port_scanner",
        ])
        assert log_path.exists() and log_path.stat().st_size > 0, "expected a real audit log to have been written"
        return auth_path, log_path

    def _status_audit_line(self, auth_path, log_path) -> str:
        from redteam_toolkit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["status", "--authorization", str(auth_path), "--audit-log", str(log_path)])
        line = next((ln for ln in result.output.splitlines() if "Audit log" in ln), "")
        return line

    def test_clean_real_log_reports_ok(self):
        with tempfile.TemporaryDirectory() as d:
            auth_path, log_path = self._real_log(d)
            line = self._status_audit_line(auth_path, log_path)
            assert "OK" in line
            assert "TAMPERED" not in line

    def test_sed_edited_field_reports_tampered(self):
        """A real sed-style field edit on disk, not an API-constructed
        tampered entry."""
        with tempfile.TemporaryDirectory() as d:
            auth_path, log_path = self._real_log(d)
            content = log_path.read_text()
            tampered = content.replace('"198.51.100.5"', '"10.0.0.1"', 1)
            assert tampered != content, "sed-style replacement should have changed something"
            log_path.write_text(tampered)

            line = self._status_audit_line(auth_path, log_path)
            assert "TAMPERED" in line

    def test_deleted_line_reports_tampered(self):
        """Adds a second real action so there's a non-final line to
        delete, then removes it with a real line-delete operation."""
        from redteam_toolkit.cli import cli
        with tempfile.TemporaryDirectory() as d:
            auth_path, log_path = self._real_log(d)
            runner = self._runner()
            runner.invoke(cli, [
                "recon", "198.51.100.5", "--authorization", str(auth_path),
                "--audit-log", str(log_path), "--modules", "fingerprint",
            ])

            lines = log_path.read_text().splitlines()
            assert len(lines) >= 2
            del lines[0]
            log_path.write_text("\n".join(lines) + "\n")

            line = self._status_audit_line(auth_path, log_path)
            assert "TAMPERED" in line

    def test_reordered_lines_reports_tampered(self):
        from redteam_toolkit.cli import cli
        with tempfile.TemporaryDirectory() as d:
            auth_path, log_path = self._real_log(d)
            runner = self._runner()
            runner.invoke(cli, [
                "recon", "198.51.100.5", "--authorization", str(auth_path),
                "--audit-log", str(log_path), "--modules", "fingerprint",
            ])

            lines = log_path.read_text().splitlines()
            assert len(lines) >= 2
            lines[0], lines[1] = lines[1], lines[0]
            log_path.write_text("\n".join(lines) + "\n")

            line = self._status_audit_line(auth_path, log_path)
            assert "TAMPERED" in line

    def test_truncation_of_most_recent_entry_is_a_known_undetectable_gap(self):
        """Documents a real, confirmed limitation found during this
        audit: deleting the LAST (most recent) line of a real log
        leaves the remaining chain perfectly valid, since nothing
        downstream references what's missing — this is inherent to a
        pure hash chain with no external anchor (the same way deleting
        the most recent git commits, with no other clone holding them,
        leaves the remaining history looking perfectly normal).

        This test deliberately asserts the CURRENT (limited) behavior
        rather than silently ignoring it, so this gap can't regress
        further (e.g. into reporting a wrong/crashing result) without a
        test failing, and so any future improvement to address this
        (e.g. an external checkpoint mechanism) has a clear test to
        update instead of accidentally "fixing" this assertion away
        without noticing what it represents. See verify_log_integrity's
        own docstring for the full explanation and the entry_count field
        added specifically so operators can track this out-of-band."""
        with tempfile.TemporaryDirectory() as d:
            auth_path, log_path = self._real_log(d)
            lines = log_path.read_text().splitlines()
            assert len(lines) == 1

            del lines[-1]
            log_path.write_text("\n".join(lines) + "\n" if lines else "")

            line = self._status_audit_line(auth_path, log_path)
            # Confirmed current behavior: truncating to an empty log
            # reports "none yet", not "TAMPERED" -- there's no chain
            # left to walk at all, so this is technically correct per
            # verify_log_integrity's own contract (an absent/empty log
            # is valid), but it's the same underlying gap: a fully
            # truncated log gives no signal that entries used to exist.
            assert "TAMPERED" not in line

    def test_entry_count_reflects_only_verified_entries_before_a_break(self):
        """verify_log_integrity's entry_count return value, added as
        part of this audit, should reflect entries successfully
        verified BEFORE a break was found -- not the raw line count of
        the (possibly tampered) file -- giving an operator an accurate
        sense of how much of the log they can actually trust."""
        from redteam_toolkit.cli import cli
        with tempfile.TemporaryDirectory() as d:
            auth_path, log_path = self._real_log(d)
            runner = self._runner()
            runner.invoke(cli, [
                "recon", "198.51.100.5", "--authorization", str(auth_path),
                "--audit-log", str(log_path), "--modules", "fingerprint",
            ])
            runner.invoke(cli, [
                "recon", "198.51.100.5", "--authorization", str(auth_path),
                "--audit-log", str(log_path), "--modules", "endpoint_discovery",
            ])

            lines = log_path.read_text().splitlines()
            assert len(lines) >= 3
            # Tamper with the SECOND entry -- the first should still
            # verify successfully before the break is hit.
            tampered_second = json.loads(lines[1])
            tampered_second["target"] = "tampered"
            lines[1] = json.dumps(tampered_second)
            log_path.write_text("\n".join(lines) + "\n")

            result = runner.invoke(cli, ["status", "--authorization", str(auth_path), "--audit-log", str(log_path)])
            # Checked against the full output (collapsing Rich's terminal-
            # width line wrapping), not a single isolated line, since the
            # wrap point can legitimately fall in the middle of this
            # phrase depending on CliRunner's simulated terminal width.
            collapsed = " ".join(result.output.split())
            assert "TAMPERED" in collapsed
            assert "chain broken at line 2" in collapsed
            assert "1 entries verified before the break" in collapsed


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


class TestSessionHeaderCLI:
    """Confirms --session-header is correctly parsed and threaded through
    to Engagement.auth_headers() via the real CLI invocation path — the
    full authenticated-discovery behaviour itself (the actual HTTP
    request carrying the header) is verified separately in
    tests/recon/test_endpoint_discovery.py::TestAuthenticatedScanning
    against the real mock-target server, which is the right level for
    that; this is specifically about the CLI option parsing/wiring."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_malformed_session_header_rejected_with_usage_error(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com"], "excluded_targets": [],
                "allowed_categories": ["recon"],
            })
            result = runner.invoke(cli, [
                "recon", "a.staging.example.com", "--authorization", str(path),
                "--session-header", "no-colon-here", "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 2
            assert "Name: Value" in result.output

    def test_well_formed_session_header_accepted_recon(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com"], "excluded_targets": [],
                "allowed_categories": ["recon"],
            })
            result = runner.invoke(cli, [
                "recon", "a.staging.example.com", "--authorization", str(path),
                "--session-header", "Cookie: session=abc123", "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output

    def test_well_formed_session_header_accepted_vuln_id(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com"], "excluded_targets": [],
                "allowed_categories": ["vuln-id"],
            })
            result = runner.invoke(cli, [
                "vuln-id", "a.staging.example.com", "--authorization", str(path),
                "--session-header", "Cookie: session=abc123", "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output

    def test_well_formed_session_header_accepted_active(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com"], "excluded_targets": [],
                "allowed_categories": ["active"],
            })
            result = runner.invoke(cli, [
                "active", "a.staging.example.com", "--authorization", str(path),
                "--confirm", "test-2026-q1",
                "--session-header", "Cookie: session=abc123", "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output


class TestDiffCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def _seed(self, db_path, engagement_id="test-2026-q1"):
        from redteam_toolkit.core.history import register_engagement, save_module_result
        from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity

        register_engagement(db_path, engagement_id, "Example Corp", "Jane Doe, CISO",
                             ["198.51.100.0/24"], "2026-01-01", "2026-01-07")
        run1 = save_module_result(db_path, engagement_id, "198.51.100.5", ModuleResult(
            module="port_scanner",
            findings=[Finding(module="port_scanner", title="Open port: 22", severity=Severity.LOW,
                               category=FindingCategory.RECON, target="198.51.100.5")],
        ))
        save_module_result(db_path, engagement_id, "198.51.100.5", ModuleResult(module="port_scanner", findings=[]))
        run3 = save_module_result(db_path, engagement_id, "198.51.100.5", ModuleResult(
            module="subdomain_takeover",
            findings=[Finding(module="subdomain_takeover", title="Possible takeover",
                               severity=Severity.HIGH, category=FindingCategory.RECON, target="198.51.100.5")],
        ))
        return run1, run3

    def test_diff_previous_latest_shows_new_finding_and_exits_nonzero(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")
            self._seed(db_path)

            result = runner.invoke(cli, ["diff", "previous", "latest", "--authorization", str(auth_path), "--db", db_path])
            assert "New findings" in result.output
            assert "Possible takeover" in result.output
            assert "Regression" in result.output
            assert result.exit_code == 1

    def test_diff_json_output(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")
            run1, run3 = self._seed(db_path)

            result = runner.invoke(cli, [
                "diff", str(run1), str(run3), "--authorization", str(auth_path), "--db", db_path, "--json",
            ])
            import json as _json
            data = _json.loads(result.output)
            assert data["run1"] == run1
            assert data["run2"] == run3
            assert len(data["resolved"]) == 1
            assert data["resolved"][0]["title"] == "Open port: 22"

    def test_diff_json_output_with_long_description_stays_valid_json(self):
        """Regression test for a real, reproduced bug found via the
        sibling integration-test-job audit: `diff --json` used
        `console.print(json.dumps(...))` -- Rich wraps text to the
        terminal width by default, which silently injects real newline
        characters into the middle of long JSON string values (a
        finding's description or evidence text), producing output that
        LOOKS like JSON but fails `json.loads()`. The existing test
        above never caught this because its seeded findings all have
        short titles with no long description text to wrap. This test
        deliberately uses a description long enough to exceed a typical
        terminal width (80 cols) on a single logical line, confirmed
        by actually reproducing the JSONDecodeError before fixing it,
        not assumed from reading the code."""
        from redteam_toolkit.cli import cli
        from redteam_toolkit.core.history import register_engagement, save_module_result
        from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")

            long_description = (
                "Injecting a single quote into the 'id' parameter produced a "
                "database error signature consistent with a SQL injection "
                "vulnerability — this description is deliberately long enough "
                "to exceed a typical 80-column terminal width on its own."
            )
            register_engagement(db_path, "test-2026-q1", "Example Corp", "Jane Doe, CISO",
                                 ["198.51.100.0/24"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db_path, "test-2026-q1", "x", ModuleResult(module="a", findings=[]))
            run2 = save_module_result(db_path, "test-2026-q1", "x", ModuleResult(
                module="sqli_detection",
                findings=[Finding(
                    module="sqli_detection", title="Possible SQL injection in parameter 'id'",
                    severity=Severity.CRITICAL, category=FindingCategory.ACTIVE, target="x",
                    description=long_description,
                )],
            ))

            result = runner.invoke(cli, [
                "diff", str(run1), str(run2), "--authorization", str(auth_path), "--db", db_path, "--json",
            ])
            import json as _json
            # This is the actual regression check: must not raise JSONDecodeError.
            data = _json.loads(result.output)
            assert data["new"][0]["description"] == long_description

    def test_diff_missing_db_errors_clearly(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            result = runner.invoke(cli, [
                "diff", "1", "2", "--authorization", str(auth_path), "--db", str(Path(d) / "nope.db"),
            ])
            assert result.exit_code != 0
            assert "not found" in result.output.lower()

    def test_diff_invalid_run_ref_errors_clearly(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")
            self._seed(db_path)
            result = runner.invoke(cli, [
                "diff", "yesterday", "latest", "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result.exit_code != 0
            assert "invalid run reference" in result.output.lower()

    def test_diff_no_regression_when_no_new_high_severity(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")
            from redteam_toolkit.core.history import register_engagement, save_module_result
            from redteam_toolkit.core.models import ModuleResult

            register_engagement(db_path, "test-2026-q1", "Example Corp", "Jane Doe, CISO",
                                 ["198.51.100.0/24"], "2026-01-01", "2026-01-07")
            run1 = save_module_result(db_path, "test-2026-q1", "x", ModuleResult(module="a", findings=[]))
            run2 = save_module_result(db_path, "test-2026-q1", "x", ModuleResult(module="a", findings=[]))

            result = runner.invoke(cli, [
                "diff", str(run1), str(run2), "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result.exit_code == 0
            assert "No regression" in result.output


class TestServeMissingDashboardDeps:
    """Regression tests for a real, reproduced bug found via systematic
    end-to-end audit (built the real wheel, installed in a clean venv,
    ran every README command literally): the exact same class of bug
    already found and fixed in the sibling secureaudit repo — only
    `import uvicorn` was guarded, and the error message's own
    '[dashboard]' got silently stripped by Rich's console markup parser
    (square brackets are markup tag syntax) instead of printed
    literally."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    @staticmethod
    def _block_import(*names):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name in names:
                raise ImportError(f"simulated: {name} not installed")
            return real_import(name, *args, **kwargs)
        return fake_import

    def test_missing_uvicorn_shows_clean_message_with_brackets_intact(self):
        import builtins
        from unittest.mock import patch

        from redteam_toolkit.cli import cli
        runner = self._runner()
        with patch.object(builtins, "__import__", side_effect=self._block_import("uvicorn")):
            result = runner.invoke(cli, ["serve"])
        assert result.exit_code == 1
        assert "Dashboard dependencies missing" in result.output
        assert "redteam-toolkit[dashboard]" in result.output
        assert "Traceback" not in result.output

    def test_missing_fastapi_shows_clean_message_not_raw_traceback(self):
        """The specific bug: uvicorn present, fastapi absent."""
        import builtins
        from unittest.mock import patch

        from redteam_toolkit.cli import cli
        runner = self._runner()
        with patch.object(builtins, "__import__", side_effect=self._block_import("fastapi")):
            result = runner.invoke(cli, ["serve"])
        assert result.exit_code == 1
        assert "Dashboard dependencies missing" in result.output
        assert "redteam-toolkit[dashboard]" in result.output
        assert "Traceback" not in result.output
        assert "ModuleNotFoundError" not in result.output


# ── Documentation freshness ───────────────────────────────────────────────────

class TestDocumentationFreshness:
    """Confirms the README's project structure tree and module-name usage
    examples stay in sync with the real source tree and the CLI's actual
    registered module names — the same class of drift (README claiming
    something that's since gone stale) found and fixed in the sibling
    secureaudit repo (#32 there), adapted to this project's actual shape:
    there's no single numeric '**N tests**' claim to verify here (the CI
    section deliberately uses a fuzzy '390+' for exactly this reason), but
    there IS a project structure tree listing individual module files and
    README usage examples naming specific --modules values, either of
    which can silently go stale the same way."""

    def _readme_text(self) -> str:
        return (Path(__file__).parent.parent / "README.md").read_text()

    def _project_structure_section(self) -> str:
        readme = self._readme_text()
        start = readme.index("## Project structure")
        # Up to the next top-level '## ' heading after this one.
        next_heading = readme.index("\n## ", start + len("## Project structure"))
        return readme[start:next_heading]

    def test_every_source_module_appears_in_readme_tree(self):
        """Every .py file under redteam_toolkit/ (excluding __init__.py)
        must be named somewhere in the README's project structure tree.
        Catches a module added without updating the tree -- this is how
        recon/base.py was found missing during the audit that created
        this test."""
        import redteam_toolkit
        pkg_root = Path(redteam_toolkit.__file__).parent
        tree_section = self._project_structure_section()

        missing = []
        for py_file in sorted(pkg_root.rglob("*.py")):
            if py_file.name == "__init__.py" or "__pycache__" in py_file.parts:
                continue
            if py_file.name not in tree_section:
                missing.append(str(py_file.relative_to(pkg_root.parent)))

        assert not missing, (
            f"These source files aren't mentioned in README's project structure "
            f"tree: {missing}. Add them to the tree (or remove the file if it's "
            f"genuinely unused)."
        )

    def test_every_module_name_in_readme_examples_is_actually_registered(self):
        """Parses '--modules X,Y,Z' occurrences in the README's bash code
        blocks and confirms each named module is a real key in cli.py's
        recon/vuln-id/active 'available' dicts -- catches the inverse
        drift: a README example referencing a renamed or removed module."""
        import re

        readme = self._readme_text()
        module_refs = set()
        for match in re.finditer(r"--modules\s+([a-z_,]+)", readme):
            module_refs.update(match.group(1).split(","))

        assert module_refs, "Expected to find at least one --modules example in the README"

        cli_source = Path(__file__).parent.parent / "redteam_toolkit" / "cli.py"
        cli_text = cli_source.read_text()
        registered = set(re.findall(r'"([a-z_]+)":\s*lambda:\s*\w+Module', cli_text))

        unknown = module_refs - registered
        assert not unknown, (
            f"README examples reference module(s) not found in cli.py's "
            f"registered modules: {unknown}. Either the module was renamed/"
            f"removed, or this is a typo in the README."
        )
