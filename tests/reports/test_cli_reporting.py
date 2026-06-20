from __future__ import annotations

import datetime
import tempfile
from pathlib import Path

import yaml
from click.testing import CliRunner

from redteam_toolkit.cli import cli


def _write_auth(path: Path, categories: list[str]) -> str:
    now = datetime.datetime.now(datetime.UTC)
    engagement_id = "cli-report-test"
    path.write_text(yaml.safe_dump({
        "engagement_id": engagement_id,
        "authorized_by": "Jane Doe",
        "authorized_contact_email": "jane@example.com",
        "client": "Acme Corp",
        "scope": {"targets": ["127.0.0.1"], "allowed_categories": categories},
        "window": {
            "start": (now - datetime.timedelta(hours=1)).isoformat(),
            "end": (now + datetime.timedelta(days=1)).isoformat(),
        },
        "confirmation_phrase": "confirmed",
    }))
    return engagement_id


class TestReconDbPersistence:
    def test_recon_with_db_persists_results(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            engagement_id = _write_auth(auth_path, ["recon"])
            db = str(Path(d) / "eng.db")

            result = runner.invoke(cli, [
                "recon", "127.0.0.1", "--authorization", str(auth_path),
                "--db", db, "--modules", "port_scanner",
            ])
            assert result.exit_code == 0, result.output

            from redteam_toolkit.core.history import load_module_results
            results = load_module_results(db, engagement_id)
            assert len(results) == 1
            assert results[0].module == "port_scanner"

    def test_recon_without_db_does_not_create_file(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth(auth_path, ["recon"])

            result = runner.invoke(cli, [
                "recon", "127.0.0.1", "--authorization", str(auth_path),
                "--modules", "port_scanner",
            ])
            assert result.exit_code == 0
            assert not (Path(d) / "eng.db").exists()


class TestReportCommand:
    def test_generates_html_report(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth(auth_path, ["recon"])
            db = str(Path(d) / "eng.db")

            runner.invoke(cli, [
                "recon", "127.0.0.1", "--authorization", str(auth_path),
                "--db", db, "--modules", "port_scanner",
            ])

            output_base = str(Path(d) / "myreport")
            result = runner.invoke(cli, [
                "report", "--authorization", str(auth_path), "--db", db,
                "--format", "html", "--output", output_base,
            ])
            assert result.exit_code == 0, result.output
            assert Path(f"{output_base}-report.html").exists()

    def test_generates_pdf_report(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth(auth_path, ["recon"])
            db = str(Path(d) / "eng.db")

            runner.invoke(cli, [
                "recon", "127.0.0.1", "--authorization", str(auth_path),
                "--db", db, "--modules", "port_scanner",
            ])

            output_base = str(Path(d) / "myreport")
            result = runner.invoke(cli, [
                "report", "--authorization", str(auth_path), "--db", db,
                "--format", "pdf", "--output", output_base,
            ])
            assert result.exit_code == 0, result.output
            pdf_path = Path(f"{output_base}-report.pdf")
            assert pdf_path.exists()
            assert pdf_path.read_bytes()[:5] == b"%PDF-"

    def test_generates_both_formats(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            _write_auth(auth_path, ["recon"])
            db = str(Path(d) / "eng.db")

            runner.invoke(cli, [
                "recon", "127.0.0.1", "--authorization", str(auth_path),
                "--db", db, "--modules", "port_scanner",
            ])

            output_base = str(Path(d) / "myreport")
            result = runner.invoke(cli, [
                "report", "--authorization", str(auth_path), "--db", db,
                "--format", "both", "--output", output_base,
            ])
            assert result.exit_code == 0
            assert Path(f"{output_base}-report.html").exists()
            assert Path(f"{output_base}-report.pdf").exists()

    def test_combines_results_across_separate_invocations(self):
        """recon and active run as separate CLI invocations but must
        combine into one report when both wrote to the same --db."""
        from tests.fixtures.mock_target.server import start_mock_target

        runner = CliRunner()
        server, port = start_mock_target()
        try:
            with tempfile.TemporaryDirectory() as d:
                auth_path = Path(d) / "authorization.yml"
                engagement_id = _write_auth(auth_path, ["recon", "active"])
                db = str(Path(d) / "eng.db")

                runner.invoke(cli, [
                    "recon", "127.0.0.1", "--authorization", str(auth_path),
                    "--db", db, "--modules", "port_scanner",
                ])
                runner.invoke(cli, [
                    "active", f"http://127.0.0.1:{port}/vulnerable/sqli",
                    "--authorization", str(auth_path), "--confirm", engagement_id,
                    "--db", db, "--modules", "sqli_detection",
                ])

                output_base = str(Path(d) / "combined")
                result = runner.invoke(cli, [
                    "report", "--authorization", str(auth_path), "--db", db,
                    "--format", "html", "--output", output_base,
                ])
                assert result.exit_code == 0
                html = Path(f"{output_base}-report.html").read_text()
                assert "port_scanner" in html
                assert "sqli_detection" in html
                assert "SQL injection" in html
        finally:
            server.shutdown()

    def test_invalid_authorization_refused(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as d:
            auth_path = Path(d) / "authorization.yml"
            auth_path.write_text("engagement_id: only-this\n")
            db = str(Path(d) / "eng.db")

            result = runner.invoke(cli, [
                "report", "--authorization", str(auth_path), "--db", db,
            ])
            assert result.exit_code != 0


class TestServeCommand:
    def test_serve_help_works(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "authenticated" in result.output.lower() or "auth" in result.output.lower()
