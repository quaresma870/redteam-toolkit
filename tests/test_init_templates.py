from __future__ import annotations

import pytest
import yaml
from click.testing import CliRunner

from redteam_toolkit.cli import cli

_TEMPLATES = ["web-app", "network", "internal-redteam"]


class TestInitTemplate:
    @pytest.mark.parametrize("template", _TEMPLATES)
    def test_writes_template(self, tmp_path, template):
        runner = CliRunner()
        out = tmp_path / "auth.yml"
        result = runner.invoke(cli, ["init", "--output", str(out), "--template", template])
        assert result.exit_code == 0
        assert out.exists()

    @pytest.mark.parametrize("template", _TEMPLATES)
    def test_never_prefills_scope_dates_or_confirmation(self, tmp_path, template):
        """The core safety property every template must preserve — reducing
        boilerplate must never mean pre-filling the fields that actually
        gate authorization."""
        runner = CliRunner()
        out = tmp_path / "auth.yml"
        runner.invoke(cli, ["init", "--output", str(out), "--template", template])
        content = out.read_text()

        assert 'engagement_id: ""' in content
        assert 'confirmation_phrase: ""' in content
        assert 'targets: []' in content
        assert '  start: ""' in content
        assert '  end: ""' in content

    @pytest.mark.parametrize("template", _TEMPLATES)
    def test_template_as_filled_in_passes_validation(self, tmp_path, template):
        """Confirms each template is structurally valid YAML matching the
        authorization schema once filled in — not just plausible-looking text."""
        import datetime

        from redteam_toolkit.core.authorization import load_authorization

        runner = CliRunner()
        out = tmp_path / "auth.yml"
        runner.invoke(cli, ["init", "--output", str(out), "--template", template])

        raw = out.read_text()
        data = yaml.safe_load(raw)
        now = datetime.datetime.now(datetime.UTC)
        data["engagement_id"] = "test-eng"
        data["authorized_by"] = "Test User"
        data["authorized_contact_email"] = "test@example.com"
        data["client"] = "Test Co"
        data["scope"]["targets"] = ["127.0.0.1"]
        data["scope"]["allowed_categories"] = ["recon"]
        data["window"]["start"] = (now - datetime.timedelta(hours=1)).isoformat()
        data["window"]["end"] = (now + datetime.timedelta(days=1)).isoformat()
        data["confirmation_phrase"] = "confirmed"

        filled_path = tmp_path / "filled.yml"
        filled_path.write_text(yaml.safe_dump(data))

        auth = load_authorization(filled_path)  # must not raise
        assert auth.engagement_id == "test-eng"

    def test_invalid_template_name_rejected(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "auth.yml"
        result = runner.invoke(cli, ["init", "--output", str(out), "--template", "nonexistent-type"])
        assert result.exit_code != 0

    def test_no_template_uses_generic(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "auth.yml"
        result = runner.invoke(cli, ["init", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    @pytest.mark.parametrize("template", _TEMPLATES)
    def test_rate_limits_example_commented_out_not_active(self, tmp_path, template):
        """Templates suggest rate_limits values as a comment — must not
        accidentally ship as live YAML that silently changes behaviour."""
        import datetime

        from redteam_toolkit.core.authorization import load_authorization

        runner = CliRunner()
        out = tmp_path / "auth.yml"
        runner.invoke(cli, ["init", "--output", str(out), "--template", template])

        data = yaml.safe_load(out.read_text())
        assert "rate_limits" not in data  # commented out, not parsed as live YAML

        # Sanity: confirm the file is still loadable once minimally filled in
        now = datetime.datetime.now(datetime.UTC)
        data["engagement_id"] = "x"
        data["authorized_by"] = "x"
        data["authorized_contact_email"] = "x@x.com"
        data["client"] = "x"
        data["scope"]["targets"] = ["127.0.0.1"]
        data["window"]["start"] = (now - datetime.timedelta(hours=1)).isoformat()
        data["window"]["end"] = (now + datetime.timedelta(days=1)).isoformat()
        data["confirmation_phrase"] = "x"
        filled = tmp_path / "filled.yml"
        filled.write_text(yaml.safe_dump(data))
        auth = load_authorization(filled)
        assert auth.rate_limits is None
