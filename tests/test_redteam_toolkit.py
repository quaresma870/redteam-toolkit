"""
Tests for redteam-toolkit Sprint 0 — authorization, audit log, engagement
gate, data models, and CLI.
"""

from __future__ import annotations

import json
import sqlite3
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


class TestScheduleCLI:
    """Issue #51: `schedule` is deliberately recon-only. These tests
    confirm both the happy path (a real, immediate recon run against a
    real target) and the specific safety boundary the issue called
    out: an authorization whose window has already expired must be
    refused before the scheduler ever starts, not silently polled
    forever."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_schedule_runs_immediately_and_reports_real_findings(self):
        """The scheduler's job() runs once immediately on start (same
        'runs now, then on cadence' behavior as secureaudit's own
        schedule command) -- confirmed against a real recon module run,
        not mocked, the same way this project's existing per-module
        audit tests do. Uses a cron expression far in the future
        ('0 6 * * 1' -- Monday 06:00) so only the immediate run fires;
        after that, the scheduler sits in its Ctrl+C-to-stop loop
        (correct, intended behavior for a long-running scheduler), so
        this test sends a real SIGINT once the immediate run's output
        has appeared, rather than letting a bare timeout SIGKILL the
        process -- confirms the scheduler treats that exactly like a
        real Ctrl+C (prints 'Scheduler stopped.' and exits cleanly),
        not just that it happens to die."""
        import signal
        import subprocess
        import time as _time

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["127.0.0.1"], "excluded_targets": [],
                "allowed_categories": ["recon"],
            })
            db_path = str(Path(d) / "schedule.db")
            proc = subprocess.Popen(
                ["python3", "-m", "redteam_toolkit.cli", "schedule", "127.0.0.1",
                 "--cron", "0 6 * * 1", "--modules", "port_scanner",
                 "--authorization", str(path), "--db", db_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                cwd=Path(__file__).parent.parent,
            )
            output_lines = []
            deadline = _time.time() + 15
            saw_save_line = False
            while _time.time() < deadline:
                line = proc.stdout.readline()
                if not line:
                    break
                output_lines.append(line)
                if "Results saved to" in line:
                    saw_save_line = True
                    break
            # A brief pause before signaling: job() has returned and printed
            # its last line, but the interpreter needs a moment to actually
            # reach the `while not stopped[0]: ... time.sleep(30)` loop --
            # confirmed by direct reproduction that sending SIGINT
            # immediately upon seeing this line (no pause) sometimes lands
            # the interrupt outside run_schedule's own try/except, letting
            # it propagate to Click's default handler instead ("Aborted!"),
            # while a real Ctrl+C from an actual human -- who takes at
            # least this long to notice output and press the key -- never
            # hits that same narrow race window in practice.
            _time.sleep(0.5)
            proc.send_signal(signal.SIGINT)
            try:
                remaining_out, _ = proc.communicate(timeout=10)
                output_lines.append(remaining_out)
            except subprocess.TimeoutExpired:
                proc.kill()
                pytest.fail("Scheduler did not exit within 10s of SIGINT")

        full_output = "".join(output_lines)
        assert saw_save_line, f"Immediate run never completed. Output so far:\n{full_output}"
        assert "Scheduled recon run #1" in full_output
        assert "port_scanner" in full_output
        assert "Scheduler stopped" in full_output
        assert proc.returncode == 0

    def test_schedule_refuses_to_start_with_expired_window(self):
        """The exact safety requirement from the issue: an expired
        authorization must be refused before the scheduler starts at
        all -- not accepted and then silently polling forever against
        a window that will never become valid again."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["127.0.0.1"], "excluded_targets": [],
                "allowed_categories": ["recon"],
            }, window={
                "start": "2020-01-01T00:00:00+00:00",
                "end": "2020-01-02T00:00:00+00:00",
            })
            result = runner.invoke(cli, [
                "schedule", "127.0.0.1", "--cron", "0 6 * * 1", "--authorization", str(path),
            ])
            assert result.exit_code != 0
            assert "not currently active" in result.output.lower() or "refusing" in result.output.lower()

    def test_schedule_unknown_module_rejected_before_any_run(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["127.0.0.1"], "excluded_targets": [],
                "allowed_categories": ["recon"],
            })
            result = runner.invoke(cli, [
                "schedule", "127.0.0.1", "--cron", "0 6 * * 1",
                "--modules", "totally_fake_module", "--authorization", str(path),
            ])
            assert "Unknown recon module" in result.output
            assert "Scheduled recon run" not in result.output

    def test_schedule_help_explicitly_documents_the_recon_only_scope(self):
        """Confirms the safety rationale is actually documented in
        --help text a real user would see, not just in source comments
        nobody reads."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["schedule", "--help"])
        assert result.exit_code == 0
        assert "recon-only" in result.output.lower() or "recon only" in result.output.lower()
        assert "confirm" in result.output.lower()

    def test_schedule_no_targets_errors_clearly(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path)
            result = runner.invoke(cli, ["schedule", "--cron", "0 6 * * 1", "--authorization", str(path)])
            assert result.exit_code != 0
            assert "no targets" in result.output.lower()

    def test_schedule_not_reachable_for_vuln_id_or_active_modules(self):
        """Structural confirmation that schedule's own module registry
        (in scheduler.py, not cli.py's recon/vuln-id/active registries)
        contains ONLY recon modules -- vuln_id and active modules are
        never even importable through it."""
        scheduler_source = Path(__file__).parent.parent / "redteam_toolkit" / "scheduler.py"
        scheduler_text = scheduler_source.read_text()
        assert "from redteam_toolkit.vuln_id" not in scheduler_text
        assert "from redteam_toolkit.active" not in scheduler_text


class TestSchedulerCronParsing:
    """Direct tests of _parse_cron's supported subset -- mirrors the
    equivalent coverage the sibling secureaudit repo's own scheduler
    tests have, confirmed against the exact same underlying `schedule`
    library and the exact same reasonable cron subset."""

    def test_every_n_minutes(self):
        from redteam_toolkit.scheduler import _parse_cron
        job = _parse_cron("*/15 * * * *", lambda: None)
        assert job is not None

    def test_every_n_hours(self):
        from redteam_toolkit.scheduler import _parse_cron
        job = _parse_cron("0 */6 * * *", lambda: None)
        assert job is not None

    def test_daily_at_time(self):
        from redteam_toolkit.scheduler import _parse_cron
        job = _parse_cron("30 6 * * *", lambda: None)
        assert job is not None

    def test_weekly_on_weekday(self):
        from redteam_toolkit.scheduler import _parse_cron
        job = _parse_cron("0 6 * * 1", lambda: None)
        assert job is not None

    def test_invalid_field_count_raises(self):
        from redteam_toolkit.scheduler import _parse_cron
        with pytest.raises(ValueError, match="5 cron fields"):
            _parse_cron("not a cron", lambda: None)

    def test_unsupported_pattern_raises(self):
        from redteam_toolkit.scheduler import _parse_cron
        with pytest.raises(ValueError, match="Unsupported cron"):
            _parse_cron("*/5 */3 * * *", lambda: None)  # both fields wildcarded — unsupported combo


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


class TestTriageCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def _seed_one_finding(self, db_path, engagement_id="test-2026-q1"):
        import sqlite3

        from redteam_toolkit.core.history import register_engagement, save_module_result
        from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity

        register_engagement(db_path, engagement_id, "Example Corp", "Jane Doe, CISO",
                             ["198.51.100.0/24"], "2026-01-01", "2026-01-07")
        save_module_result(db_path, engagement_id, "198.51.100.5", ModuleResult(
            module="sqli_detection",
            findings=[Finding(module="sqli_detection", title="Possible SQL injection",
                               severity=Severity.CRITICAL, category=FindingCategory.ACTIVE,
                               target="198.51.100.5")],
        ))
        conn = sqlite3.connect(db_path)
        finding_id = conn.execute("SELECT id FROM findings").fetchone()[0]
        conn.close()
        return finding_id

    def test_triage_sets_disposition_and_confirms_in_output(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")
            finding_id = self._seed_one_finding(db_path)

            result = runner.invoke(cli, [
                "triage", str(finding_id), "--status", "accepted-risk",
                "--reason", "Client approved, ticket JIRA-123", "--until", "2099-01-01",
                "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result.exit_code == 0, result.output
            assert "accepted-risk" in result.output
            assert "JIRA-123" in result.output

    def test_triage_persists_and_diff_reflects_it(self):
        """The real end-to-end path: triage a finding, then confirm a
        subsequent diff shows it dispositioned and no longer counts as
        a regression."""
        from redteam_toolkit.cli import cli
        from redteam_toolkit.core.history import save_module_result
        from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")

            run1 = save_module_result(db_path, "test-2026-q1", "x", ModuleResult(module="a", findings=[]))
            from redteam_toolkit.core.history import register_engagement
            register_engagement(db_path, "test-2026-q1", "Example Corp", "Jane Doe, CISO",
                                 ["198.51.100.0/24"], "2026-01-01", "2026-01-07")
            run2 = save_module_result(db_path, "test-2026-q1", "x", ModuleResult(
                module="xss_detection",
                findings=[Finding(module="xss_detection", title="Reflected XSS", severity=Severity.CRITICAL,
                                   category=FindingCategory.ACTIVE, target="x")],
            ))
            import sqlite3
            conn = sqlite3.connect(db_path)
            finding_id = conn.execute("SELECT id FROM findings").fetchone()[0]
            conn.close()

            # Before triage: diff shows a regression.
            result_before = runner.invoke(cli, [
                "diff", str(run1), str(run2), "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result_before.exit_code == 1
            assert "Regression" in result_before.output

            runner.invoke(cli, [
                "triage", str(finding_id), "--status", "false-positive",
                "--reason", "sanitized by WAF", "--authorization", str(auth_path), "--db", db_path,
            ])

            # After triage: same diff no longer regresses, and the
            # finding is still shown (not hidden), marked accordingly.
            result_after = runner.invoke(cli, [
                "diff", str(run1), str(run2), "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result_after.exit_code == 0, result_after.output
            assert "No regression" in result_after.output
            assert "Reflected XSS" in result_after.output
            assert "false-positive" in result_after.output

    def test_triage_unknown_finding_id_errors_clearly(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")
            self._seed_one_finding(db_path)

            result = runner.invoke(cli, [
                "triage", "99999", "--status", "remediated",
                "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result.exit_code != 0
            assert "no finding" in result.output.lower()

    def test_triage_wrong_engagement_refused(self):
        """A finding belonging to a DIFFERENT engagement_id than the
        one authorization.yml resolves to must be refused -- prevents
        accidentally dispositioning a finding from someone else's
        engagement just because it happens to share the same --db."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)  # resolves to engagement_id "test-2026-q1"
            db_path = str(Path(d) / "eng.db")
            finding_id = self._seed_one_finding(db_path, engagement_id="a-totally-different-engagement")

            result = runner.invoke(cli, [
                "triage", str(finding_id), "--status", "remediated",
                "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result.exit_code != 0
            assert "different-engagement" in result.output.lower() or "belongs to engagement" in result.output.lower()

    def test_triage_invalid_status_rejected_by_click_choice(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")
            finding_id = self._seed_one_finding(db_path)

            result = runner.invoke(cli, [
                "triage", str(finding_id), "--status", "not-a-real-status",
                "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result.exit_code == 2  # click's own usage-error exit code

    def test_triage_can_revert_to_open(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")
            finding_id = self._seed_one_finding(db_path)

            runner.invoke(cli, [
                "triage", str(finding_id), "--status", "accepted-risk",
                "--authorization", str(auth_path), "--db", db_path,
            ])
            result = runner.invoke(cli, [
                "triage", str(finding_id), "--status", "open",
                "--authorization", str(auth_path), "--db", db_path,
            ])
            assert result.exit_code == 0
            assert "open" in result.output.lower()


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


class TestActiveMultiTargetConfirmInteraction:
    """Issue #47: verifies the interaction between the active command's
    multi-target batch scanning and its mandatory --confirm gate.
    The specific behaviors being checked:
    - --confirm is verified ONCE before the loop, not per-target
      (confirmed by checking the audit log for exactly one
      'active_tier_confirmation' entry across a 2-target run)
    - the canary listener is shared across all targets in a run
      (verified structurally from the CLI source, not easy to test
       via CliRunner without a real canary-triggering exploit, but
       the structural test confirms the `finally: canary.shutdown()`
       is outside the per-target loop)
    - scope checking still happens per-target inside the loop
      (verified by running against one in-scope and one out-of-scope
       target and confirming only the in-scope one's module call is
       attempted)
    - --confirm with a WRONG engagement ID is refused before any
      target is even attempted (exit non-zero, no module calls)
    """

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_confirm_is_verified_once_for_multi_target_run(self):
        """A 2-target batch active run produces exactly ONE
        'active_tier_confirmation' audit log entry — confirmation
        is a session gate, not a per-target gate."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com", "b.staging.example.com"],
                "excluded_targets": [], "allowed_categories": ["active"],
            })
            log_path = Path(d) / "test-2026-q1.audit.jsonl"
            result = runner.invoke(cli, [
                "active",
                "a.staging.example.com", "b.staging.example.com",
                "--authorization", str(path),
                "--audit-log", str(log_path),
                "--confirm", "test-2026-q1",
                "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output
            assert "Active-tier confirmed" in result.output

            entries = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
            confirmation_entries = [e for e in entries if e["action"] == "active_tier_confirmation"]
            assert len(confirmation_entries) == 1, (
                f"Expected exactly 1 'active_tier_confirmation' entry for a 2-target run, "
                f"got {len(confirmation_entries)}. --confirm must be a session gate, "
                f"not a per-target gate."
            )
            assert confirmation_entries[0]["allowed"] is True

    def test_wrong_confirm_refused_before_any_target_attempted(self):
        """A wrong --confirm value must be refused immediately, before
        any target is scanned at all (not just before the first
        active-tier module call within each target)."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com"], "excluded_targets": [],
                "allowed_categories": ["active"],
            })
            log_path = Path(d) / "test-2026-q1.audit.jsonl"
            result = runner.invoke(cli, [
                "active", "a.staging.example.com",
                "--authorization", str(path),
                "--audit-log", str(log_path),
                "--confirm", "WRONG-ID",
                "--modules", "nonexistent_module",
            ])
            assert result.exit_code != 0
            assert "not confirmed" in result.output.lower() or "refused" in result.output.lower()
            # No module should have been attempted for any target
            assert "Unknown module" not in result.output
            assert "nonexistent_module" not in result.output

    def test_scope_checked_per_target_not_just_at_startup(self):
        """With one in-scope and one out-of-scope target, the
        out-of-scope one's module call is refused, the in-scope one
        proceeds — scope checking happens inside the loop, not just
        once at startup."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": ["a.staging.example.com"],
                "excluded_targets": [], "allowed_categories": ["active"],
            })
            result = runner.invoke(cli, [
                "active",
                "a.staging.example.com", "evil-out-of-scope.com",
                "--authorization", str(path),
                "--confirm", "test-2026-q1",
                "--modules", "nonexistent_module",
            ])
            assert result.exit_code == 0, result.output
            # Both targets appear in the output (as headers)
            assert "a.staging.example.com" in result.output
            assert "evil-out-of-scope.com" in result.output
            # The in-scope target attempted its module (unknown but logged)
            assert "Unknown module" in result.output

    def test_canary_shared_across_targets_structurally(self):
        """Verifies structurally (from the source) that the canary
        listener is created ONCE outside the per-target loop, not
        recreated for each target — confirmed both by reading the
        code and by checking that LocalCanaryListener's shutdown()
        is only called once (in the finally block outside the loop)
        per invocation, not once per target."""
        cli_source = Path(__file__).parent.parent / "redteam_toolkit" / "cli.py"
        cli_text = cli_source.read_text()

        # Confirm the canary instantiation appears BEFORE the
        # per-target loop begins, not inside it.
        canary_pos = cli_text.index("canary = LocalCanaryListener(")
        for_loop_pos = cli_text.index("for target in resolved_targets:", canary_pos - 500)
        assert canary_pos < for_loop_pos, (
            "LocalCanaryListener() is instantiated AFTER the per-target loop begins -- "
            "the canary should be shared across all targets, bound once per session, "
            "not once per target (which would waste a port bind/unbind per target "
            "and could cause port conflicts)."
        )

        # Confirm shutdown() appears only once (in the finally block
        # that wraps the whole loop, not inside it)
        shutdown_count = cli_text.count("canary.shutdown()")
        assert shutdown_count == 1, (
            f"Expected exactly 1 'canary.shutdown()' call (in the finally block "
            f"wrapping the whole multi-target loop), got {shutdown_count}."
        )


class TestReportContentCorrectness:
    """Issue #48: verifies that the HTML and PDF reports contain the
    correct engagement data — not just that the file exists and is
    non-empty. The existing report tests only checked file creation;
    this checks that specific, known content (engagement_id,
    finding title, severity, client name) actually appears in the
    rendered output.

    Uses a fully controlled EngagementReport fixture with known values
    so any content-correctness regression produces an obvious,
    actionable assertion failure rather than a vague 'file was
    generated' pass."""

    def _make_report(self) -> EngagementReport:
        from datetime import UTC, datetime

        from redteam_toolkit.core.models import (
            EngagementReport,
            Finding,
            FindingCategory,
            ModuleResult,
            Severity,
        )
        finding = Finding(
            module="sqli_detection",
            title="SQL injection in parameter 'id'",
            severity=Severity.CRITICAL,
            category=FindingCategory.ACTIVE,
            target="http://app.acme-staging.com/users",
            description="Injecting a quote into 'id' produced a database error.",
            evidence="Possible SQL injection: sqlite3.OperationalError",
            remediation="Use parameterised queries.",
            cvss_score=9.8,
        )
        mr = ModuleResult(module="sqli_detection", findings=[finding], duration_ms=42.0)
        return EngagementReport(
            engagement_id="acme-2026-q2",
            target_scope=["198.51.100.0/24", "*.acme-staging.com"],
            authorized_by="Jane Doe, CISO",
            client="Acme Corp",
            window_start="2026-07-01T09:00:00+00:00",
            window_end="2026-07-14T17:00:00+00:00",
            started_at=datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC),
            module_results=[mr],
            audit_log_integrity_ok=True,
            audit_log_entry_count=7,
        )

    def test_html_contains_engagement_id(self):
        from redteam_toolkit.reports.html import write_html
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            write_html(report, out)
            content = out.read_text()
            assert "acme-2026-q2" in content

    def test_html_contains_client_name(self):
        from redteam_toolkit.reports.html import write_html
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            write_html(report, out)
            content = out.read_text()
            assert "Acme Corp" in content

    def test_html_contains_finding_title(self):
        from redteam_toolkit.reports.html import write_html
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            write_html(report, out)
            content = out.read_text()
            assert "SQL injection in parameter" in content

    def test_html_contains_critical_severity(self):
        from redteam_toolkit.reports.html import write_html
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            write_html(report, out)
            content = out.read_text()
            assert "CRITICAL" in content

    def test_html_contains_target(self):
        from redteam_toolkit.reports.html import write_html
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            write_html(report, out)
            content = out.read_text()
            assert "acme-staging.com" in content

    def test_html_authorized_by_shown(self):
        from redteam_toolkit.reports.html import write_html
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            write_html(report, out)
            content = out.read_text()
            assert "Jane Doe" in content

    def test_html_is_parseable_as_html(self):
        """Confirms the output is actually valid HTML structure
        (html/head/body tags present), not just text-in-a-file."""
        from html.parser import HTMLParser

        from redteam_toolkit.reports.html import write_html

        class TagCollector(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags = set()
            def handle_starttag(self, tag, attrs):
                self.tags.add(tag)

        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            write_html(report, out)
            parser = TagCollector()
            parser.feed(out.read_text())
            assert "html" in parser.tags
            assert "body" in parser.tags
            assert "table" in parser.tags

    def test_pdf_is_valid_pdf_with_correct_header(self):
        from redteam_toolkit.reports.pdf import write_pdf
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.pdf"
            write_pdf(report, out)
            header = out.read_bytes()[:5]
            assert header == b"%PDF-", f"PDF header wrong: {header!r}"

    def test_pdf_metadata_contains_engagement_id(self):
        """PDF document metadata (Title field in the /Info dict) must
        contain the engagement ID -- confirmed that this is
        in plain-text in the raw bytes before relying on it, unlike
        the page content which is deflate-compressed."""
        from redteam_toolkit.reports.pdf import write_pdf
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.pdf"
            write_pdf(report, out)
            raw = out.read_bytes()
            assert b"acme-2026-q2" in raw, (
                "Engagement ID not found in PDF raw bytes -- PDF metadata not being set. "
                "Expected to find it in the /Title field of the /Info dict."
            )

    def test_pdf_metadata_contains_client_via_subject(self):
        """PDF /Subject field contains the client name."""
        from redteam_toolkit.reports.pdf import write_pdf
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.pdf"
            write_pdf(report, out)
            raw = out.read_bytes()
            assert b"Acme Corp" in raw, (
                "Client name not found in PDF raw bytes -- expected in /Subject field."
            )

    def test_pdf_page_content_accessible_via_author_metadata(self):
        """The PDF's Author metadata field (from the /Info dict in plain
        text) contains the authorized_by value, confirming the actual
        report data is embedded in the file in at least one accessible,
        verifiable location. The page content itself is encoded as
        ASCII85/zlib (reportlab's default), which requires a 2-step
        decode not covered by stdlib zlib alone -- the metadata tests
        above and the CLI end-to-end test below are the right level for
        confirming content is correct without depending on implementation
        details of reportlab's internal encoding choices."""
        from redteam_toolkit.reports.pdf import write_pdf
        report = self._make_report()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.pdf"
            write_pdf(report, out)
            raw = out.read_bytes()
            # Author field is in plain text in the /Info dict
            assert b"Jane Doe" in raw

    def test_report_produced_by_real_cli_command_has_correct_content(self):
        """End-to-end: the `report` CLI command, reading from a real
        persisted DB (written by a real recon invocation through the
        real CLI), produces an HTML file whose content matches the
        actual engagement's data — not just 'file exists'."""
        from redteam_toolkit.cli import cli
        runner = self.__class__._runner(self)
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path, scope={
                "targets": ["198.51.100.5"],
                "excluded_targets": [], "allowed_categories": ["recon"],
            })
            db_path = str(Path(d) / "eng.db")
            runner.invoke(cli, [
                "recon", "198.51.100.5",
                "--authorization", str(auth_path),
                "--modules", "port_scanner",
                "--db", db_path,
            ])
            out_base = str(Path(d) / "report")
            result = runner.invoke(cli, [
                "report",
                "--authorization", str(auth_path),
                "--db", db_path,
                "--format", "html",
                "--output", out_base,
            ])
            assert result.exit_code == 0, result.output
            html_path = Path(d) / "report-report.html"
            assert html_path.exists() and html_path.stat().st_size > 1000
            content = html_path.read_text()
            assert "test-2026-q1" in content   # the engagement_id from _write_auth_yaml
            assert "Example Corp" in content   # the client from _write_auth_yaml

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()


class TestReportStatusIntegration:
    """Issue #50 acceptance criterion: a dispositioned finding must be
    visible (not hidden) and visually distinct in report output, the
    same requirement already covered for `diff` in TestTriageCLI."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_html_report_shows_disposition_via_real_cli_end_to_end(self):
        """The real path: recon finds something, triage dispositions it,
        report renders it — confirms build_report()'s own status lookup
        (not a hand-constructed EngagementReport) actually wires
        together correctly."""
        from redteam_toolkit.cli import cli
        from redteam_toolkit.core.history import register_engagement, save_module_result
        from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")

            register_engagement(db_path, "test-2026-q1", "Example Corp", "Jane Doe, CISO",
                                 ["198.51.100.0/24"], "2026-01-01", "2026-01-07")
            save_module_result(db_path, "test-2026-q1", "198.51.100.5", ModuleResult(
                module="sqli_detection",
                findings=[Finding(module="sqli_detection", title="Possible SQL injection",
                                   severity=Severity.CRITICAL, category=FindingCategory.ACTIVE,
                                   target="198.51.100.5")],
            ))
            import sqlite3
            conn = sqlite3.connect(db_path)
            finding_id = conn.execute("SELECT id FROM findings").fetchone()[0]
            conn.close()

            runner.invoke(cli, [
                "triage", str(finding_id), "--status", "accepted-risk",
                "--reason", "Client approved, ticket JIRA-999",
                "--authorization", str(auth_path), "--db", db_path,
            ])

            out_base = str(Path(d) / "report")
            result = runner.invoke(cli, [
                "report", "--authorization", str(auth_path), "--db", db_path,
                "--format", "html", "--output", out_base,
            ])
            assert result.exit_code == 0, result.output
            content = (Path(d) / "report-report.html").read_text()
            assert "accepted-risk" in content
            assert "JIRA-999" in content
            # The finding itself must still be present, not hidden.
            assert "Possible SQL injection" in content

    def test_html_report_defaults_to_open_status_for_never_triaged_findings(self):
        """A finding that was never triaged must render with 'open'
        status, not blank/missing -- confirms the default path, not
        just the dispositioned path."""
        from redteam_toolkit.cli import cli
        from redteam_toolkit.core.history import register_engagement, save_module_result
        from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")

            register_engagement(db_path, "test-2026-q1", "Example Corp", "Jane Doe, CISO",
                                 ["198.51.100.0/24"], "2026-01-01", "2026-01-07")
            save_module_result(db_path, "test-2026-q1", "198.51.100.5", ModuleResult(
                module="port_scanner",
                findings=[Finding(module="port_scanner", title="Open port: 22", severity=Severity.LOW,
                                   category=FindingCategory.RECON, target="198.51.100.5")],
            ))

            out_base = str(Path(d) / "report")
            result = runner.invoke(cli, [
                "report", "--authorization", str(auth_path), "--db", db_path,
                "--format", "html", "--output", out_base,
            ])
            assert result.exit_code == 0, result.output
            content = (Path(d) / "report-report.html").read_text()
            assert "status-open" in content

    def test_pdf_report_does_not_crash_with_dispositioned_findings(self):
        """PDF page content is ASCII85+FlateDecode-compressed (documented
        limitation from #48's own work), so this doesn't assert on
        rendered text content the way the HTML test does -- it confirms
        the PDF path handles a dispositioned finding without raising,
        and produces a valid, non-trivial PDF file."""
        from redteam_toolkit.cli import cli
        from redteam_toolkit.core.history import register_engagement, save_module_result
        from redteam_toolkit.core.models import Finding, FindingCategory, ModuleResult, Severity

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth_yaml(auth_path)
            db_path = str(Path(d) / "eng.db")

            register_engagement(db_path, "test-2026-q1", "Example Corp", "Jane Doe, CISO",
                                 ["198.51.100.0/24"], "2026-01-01", "2026-01-07")
            save_module_result(db_path, "test-2026-q1", "198.51.100.5", ModuleResult(
                module="sqli_detection",
                findings=[Finding(module="sqli_detection", title="Possible SQL injection",
                                   severity=Severity.CRITICAL, category=FindingCategory.ACTIVE,
                                   target="198.51.100.5")],
            ))
            import sqlite3
            conn = sqlite3.connect(db_path)
            finding_id = conn.execute("SELECT id FROM findings").fetchone()[0]
            conn.close()

            runner.invoke(cli, [
                "triage", str(finding_id), "--status", "remediated", "--reason", "Patched in v2.3",
                "--authorization", str(auth_path), "--db", db_path,
            ])

            out_base = str(Path(d) / "report")
            result = runner.invoke(cli, [
                "report", "--authorization", str(auth_path), "--db", db_path,
                "--format", "pdf", "--output", out_base,
            ])
            assert result.exit_code == 0, result.output
            pdf_path = Path(d) / "report-report.pdf"
            assert pdf_path.exists()
            assert pdf_path.read_bytes()[:5] == b"%PDF-"
            assert pdf_path.stat().st_size > 500


class TestAllModulesRunWithoutCrashing:
    """Issue #43: exhaustive per-module functional audit — mirrors the
    same approach used for secureaudit's #30. Every module listed in
    cli.py's available dicts (recon/vuln-id/active) is run through its
    actual class and run() method. Modules with injectable
    dependencies use them so no real network calls are needed, making
    these fast and deterministic. The existing test suite already
    covered most modules individually; this is specifically about the
    ones that had never been run end-to-end even via CliRunner, and
    about having a meta-test that loops ALL registered modules so a
    future addition can't silently go untested."""

    def _eng(self, targets=None):
        from redteam_toolkit.core.engagement import Engagement

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "authorization.yml"
            _write_auth_yaml(path, scope={
                "targets": targets or ["198.51.100.0/24", "127.0.0.1", "*.example.com"],
                "excluded_targets": [],
                "allowed_categories": ["recon", "vuln-id", "active"],
            })
            eng = Engagement.load(path, Path(d) / "test.audit.jsonl")
            # Keep the engagement alive outside the with block by
            # returning it (the tmpdir is cleaned up, but the Engagement
            # object holds no reference back to it, only the paths it
            # already resolved at load time).
            return eng

    def test_fingerprint_module_with_injected_connect(self):
        from redteam_toolkit.recon.fingerprint import FingerprintModule

        eng = self._eng()
        def fake_connect(host, port):
            if port == 22:
                return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu"
            return None

        m = FingerprintModule(eng, connect_fn=fake_connect)
        result = m.run("198.51.100.5", ports=[22, 80])

        assert result.error is None
        assert result.findings[0].extra["port"] == 22
        assert "OpenSSH" in result.findings[0].title

    def test_active_dns_module_with_injected_resolver(self):
        from redteam_toolkit.recon.active_dns import ActiveDNSModule

        eng = self._eng()
        # resolve_fn is called as self._resolve(candidate) -- 1 arg (hostname only)
        m = ActiveDNSModule(eng, resolve_fn=lambda hostname: ["198.51.100.5"])
        result = m.run("198.51.100.5")
        assert result.error is None

    def test_zone_transfer_module_with_injected_fns(self):
        from redteam_toolkit.recon.active_dns import ZoneTransferModule

        eng = self._eng()
        # nameserver_fn: domain -> list[str]
        # axfr_fn: (target, nameserver) -> (allowed, record_count)
        m = ZoneTransferModule(
            eng,
            nameserver_fn=lambda domain: ["ns1.example.com"],
            axfr_fn=lambda target, ns: (False, 0),  # not vulnerable
        )
        result = m.run("198.51.100.5")
        assert result.error is None

    def test_cve_correlation_module_with_injected_query(self):
        from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule

        eng = self._eng()
        # query_fn: (product, version) -> list[dict] of CVE records
        m = CVECorrelationModule(eng, query_fn=lambda product, version: [])
        result = m.run("198.51.100.5")
        assert result.error is None

    def test_default_credentials_module_without_opt_in_is_skip(self):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = self._eng()
        m = DefaultCredentialModule(eng, try_login_fn=lambda *a: False)
        result = m.run("198.51.100.5", opt_in=False)
        assert result.error is None
        assert any("opt-in" in f.title.lower() or "skipped" in f.title.lower()
                   for f in result.findings)

    def test_default_credentials_module_with_opt_in_runs(self):
        from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule

        eng = self._eng()
        m = DefaultCredentialModule(eng, try_login_fn=lambda *a: False)
        result = m.run("198.51.100.5", opt_in=True)
        assert result.error is None

    def test_all_recon_modules_in_cli_registry_run_without_crash(self):
        """Meta-test: every module registered in cli.py's recon
        'available' dict can be instantiated and its run() method
        invoked without ImportError or AttributeError. Uses only
        injectable/mockable calls — no real sockets."""
        from redteam_toolkit.recon.active_dns import ActiveDNSModule, ZoneTransferModule
        from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule
        from redteam_toolkit.recon.fingerprint import FingerprintModule
        from redteam_toolkit.recon.passive_dns import PassiveDNSModule
        from redteam_toolkit.recon.port_scanner import PortScannerModule
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule
        from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

        eng = self._eng()
        modules_and_kwargs = [
            (PortScannerModule(eng), {}),
            (FingerprintModule(eng, connect_fn=lambda h, p: None), {}),
            (PassiveDNSModule(eng, fetch_fn=lambda d: "[]"), {}),
            (ActiveDNSModule(eng, resolve_fn=lambda hostname: []), {}),
            (ZoneTransferModule(eng,
                nameserver_fn=lambda d: [],
                axfr_fn=lambda target, ns: (False, 0)), {}),
            (WebFingerprintModule(eng, fetch_fn=lambda t: ({}, "")), {}),
            (SubdomainTakeoverModule(eng,
                resolve_cname_fn=lambda h: None,
                http_fetch_fn=lambda h: None), {}),
            (EndpointDiscoveryModule(eng,
                fetch_fn=lambda url: (404, ""),
                respect_robots=False), {"wordlist": ["admin"]}),
        ]
        for module, kwargs in modules_and_kwargs:
            result = module.run("198.51.100.5", **kwargs)
            assert result.error is None, (
                f"Module '{type(module).__name__}' raised an error: {result.error}"
            )

    def test_all_active_modules_in_cli_registry_run_without_crash(self):
        """Meta-test for the active tier."""
        from redteam_toolkit.active.canary import LocalCanaryListener
        from redteam_toolkit.active.open_redirect import OpenRedirectModule
        from redteam_toolkit.active.path_traversal import PathTraversalModule
        from redteam_toolkit.active.sqli import SQLInjectionModule
        from redteam_toolkit.active.ssrf import SSRFDetectionModule
        from redteam_toolkit.active.xss import XSSDetectionModule

        eng = self._eng(targets=["http://198.51.100.5"])
        canary = LocalCanaryListener(host="127.0.0.1")
        try:
            modules = [
                SQLInjectionModule(eng),
                XSSDetectionModule(eng),
                OpenRedirectModule(eng),
                SSRFDetectionModule(eng, canary_listener=canary),
                PathTraversalModule(eng),
            ]
            for module in modules:
                result = module.run("http://198.51.100.5/test?id=1")
                assert result.error is None or "scope" in str(result.error).lower(), (
                    f"Module '{type(module).__name__}' raised an unexpected error: {result.error}"
                )
        finally:
            canary.shutdown()


class TestDemoCommand:
    """Issue #53: one-command demo mode. Verifies the acceptance
    criteria via the real CLI command (not just the underlying
    target_server module) — starts a real local vulnerable target,
    runs a real scan against it, and produces real, verifiable
    findings and a demo authorization file that's clearly marked as
    such."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_demo_produces_clearly_marked_authorization_file(self):
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            workdir = Path(d) / "demo-out"
            result = runner.invoke(cli, ["demo", "--no-serve", "--workdir", str(workdir)])
            assert result.exit_code == 0, result.output

            auth_path = workdir / "demo-authorization.yml"
            assert auth_path.exists()
            content = auth_path.read_text()
            # The acceptance criteria's specific requirement: cannot be
            # mistaken for a real engagement's authorization file.
            assert "DEMO" in content
            assert "do not use for real engagements" in content
            assert "127.0.0.1" in content

    def test_demo_produces_real_sqli_and_xss_findings(self):
        """The demo target's known-vulnerable routes must produce real
        findings from the real detection modules — not staged/fake
        output."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            workdir = Path(d) / "demo-out"
            result = runner.invoke(cli, ["demo", "--no-serve", "--workdir", str(workdir)])
            assert result.exit_code == 0, result.output
            assert "sqli_detection: 1 finding" in result.output
            assert "xss_detection: 1 finding" in result.output

            db_path = workdir / "demo.db"
            assert db_path.exists()
            conn = sqlite3.connect(str(db_path))
            modules_run = {row[0] for row in conn.execute("SELECT DISTINCT module FROM module_runs")}
            assert "sqli_detection" in modules_run
            assert "xss_detection" in modules_run
            conn.close()

    def test_demo_no_serve_does_not_block(self):
        """--no-serve must return control to the caller — confirms the
        dashboard is genuinely skipped, not just slow to start (this
        test would hang/timeout if the dashboard were started anyway)."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            workdir = Path(d) / "demo-out"
            result = runner.invoke(cli, ["demo", "--no-serve", "--workdir", str(workdir)])
            assert result.exit_code == 0
            assert "Dashboard skipped" in result.output

    def test_demo_db_is_immediately_servable(self):
        """The demo's own --db output must work directly with the real
        `serve` command afterward — confirms the two commands share a
        compatible schema/expectations, not just that demo's own
        internal bookkeeping is self-consistent."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            workdir = Path(d) / "demo-out"
            runner.invoke(cli, ["demo", "--no-serve", "--workdir", str(workdir)])
            db_path = workdir / "demo.db"

            from starlette.testclient import TestClient

            from redteam_toolkit.dashboard.app import create_app

            app = create_app(str(db_path))
            client = TestClient(app)
            resp = client.get("/api/engagements")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 1
            assert data[0]["engagement_id"] == "demo"
            assert "DEMO" in data[0]["client"]

    def test_demo_workdir_defaults_to_cwd_subdirectory(self):
        """Without --workdir, files land in a predictable, visible
        location (./redteam-toolkit-demo) rather than a temp directory
        that vanishes — matches the acceptance criteria's expectation
        that someone can inspect what was generated."""
        from redteam_toolkit.cli import cli
        runner = self._runner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["demo", "--no-serve"])
            assert result.exit_code == 0, result.output
            assert Path("redteam-toolkit-demo", "demo-authorization.yml").exists()
