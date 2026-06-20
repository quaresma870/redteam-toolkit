"""Shared fixtures for redteam-toolkit tests."""

from __future__ import annotations

import datetime
import tempfile
from pathlib import Path

import pytest
import yaml

from redteam_toolkit.core.engagement import Engagement


@pytest.fixture
def engagement_factory():
    """Returns a callable that builds a fresh Engagement scoped to given
    targets/categories, backed by its own temp directory (kept alive for
    the lifetime of the returned Engagement)."""

    tmpdirs = []

    def _make(targets=None, allowed_categories=None, excluded_targets=None):
        tmpdir = tempfile.TemporaryDirectory()
        tmpdirs.append(tmpdir)
        now = datetime.datetime.now(datetime.UTC)

        auth_path = Path(tmpdir.name) / "authorization.yml"
        auth_path.write_text(yaml.safe_dump({
            "engagement_id": "test",
            "authorized_by": "Test User",
            "authorized_contact_email": "test@example.com",
            "client": "Test Co",
            "scope": {
                "targets": targets or ["127.0.0.1", "*.example.com"],
                "excluded_targets": excluded_targets or [],
                "allowed_categories": allowed_categories if allowed_categories is not None else ["recon"],
            },
            "window": {
                "start": (now - datetime.timedelta(hours=1)).isoformat(),
                "end": (now + datetime.timedelta(days=1)).isoformat(),
            },
            "confirmation_phrase": "I confirm",
        }))
        return Engagement.load(auth_path, Path(tmpdir.name) / "test.audit.jsonl")

    yield _make

    for t in tmpdirs:
        t.cleanup()


@pytest.fixture
def mock_target():
    """Starts the local-only mock target server for the duration of a test."""
    from tests.fixtures.mock_target.server import start_mock_target

    server, port = start_mock_target()
    yield port
    server.shutdown()
