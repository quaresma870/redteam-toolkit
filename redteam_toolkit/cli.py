"""
redteam-toolkit CLI — entry point.

Every command other than `init` requires a validated authorization.yml.
There is deliberately no `schedule` command anywhere in this tool — every
run is a single, attended, deliberate action.
"""

from __future__ import annotations

import importlib.metadata
import sys
from datetime import UTC
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.table import Table

console = Console()

try:
    __version__ = importlib.metadata.version("redteam-toolkit")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0+dev"

_TEMPLATE = """# redteam-toolkit authorization — fill in EVERY field before use.
# This file is the only thing that permits any scan to run.
# Read docs/legal-and-ethics.md before completing it.

engagement_id: ""              # unique per engagement, e.g. "acme-2026-q2"
authorized_by: ""              # full name + title of the person who approved this
authorized_contact_email: ""
client: ""                     # organisation being tested

scope:
  targets: []                  # CIDR ranges, exact IPs, or domains (supports *.example.com)
  excluded_targets: []         # explicitly carved out even if matched by a target pattern above
  allowed_categories: []       # recon, vuln-id, active — active requires extra confirmation at run time

window:
  start: ""                    # ISO 8601, e.g. "2026-07-01T00:00:00Z"
  end: ""                      # must be after start

confirmation_phrase: ""        # e.g. "I confirm authorization for acme-2026-q2"
"""


@click.group()
@click.version_option(__version__, prog_name="redteam-toolkit")
def cli():
    """🎯 redteam-toolkit — authorized penetration testing toolkit.

    Every command other than 'init' requires a validated authorization.yml.
    Run 'redteam-toolkit init' to create one, and read
    docs/legal-and-ethics.md before your first engagement.
    """


@cli.command()
@click.option("--output", "-o", default="authorization.yml", show_default=True,
              help="Path to write the authorization template.")
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def init(output, force):
    """Create an authorization.yml template.

    Every field still requires manual completion — this never auto-fills
    scope, dates, or the confirmation phrase.
    """
    path = Path(output)
    if path.exists() and not force:
        console.print(f"[red]{path} already exists.[/red] Use --force to overwrite.")
        sys.exit(1)

    path.write_text(_TEMPLATE, encoding="utf-8")
    console.print(f"[green]✔[/green] Template written: [bold]{path}[/bold]")
    console.print(
        "\n[yellow]This file does not authorize anything yet.[/yellow] "
        "Fill in every field, get explicit sign-off from the target owner, then run:\n"
        f"  [cyan]redteam-toolkit validate-scope --authorization {path}[/cyan]\n"
    )


@cli.command(name="validate-scope")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml")
def validate_scope(authorization):
    """Validate an authorization.yml — schema, time window, and scope matching."""
    from redteam_toolkit.core.authorization import AuthorizationError, load_authorization

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    console.print(f"[green]✔[/green] [bold]{authorization}[/bold] is structurally valid.\n")

    t = Table(box=box.SIMPLE_HEAD, show_header=False)
    t.add_column("Field", style="bold")
    t.add_column("Value")
    t.add_row("Engagement ID", auth.engagement_id)
    t.add_row("Client", auth.client)
    t.add_row("Authorized by", auth.authorized_by)
    t.add_row("Targets", ", ".join(auth.scope.targets))
    if auth.scope.excluded_targets:
        t.add_row("Excluded", ", ".join(auth.scope.excluded_targets))
    t.add_row("Categories", ", ".join(auth.scope.allowed_categories) or "[dim]none[/dim]")
    t.add_row("Window", f"{auth.window.start.isoformat()} → {auth.window.end.isoformat()}")
    console.print(t)

    if auth.is_within_window():
        console.print("\n[green]✔ Currently within the authorized window.[/green]\n")
    else:
        console.print("\n[yellow]⚠ Currently OUTSIDE the authorized window — scans will be refused.[/yellow]\n")


@cli.command()
@click.option("--authorization", "-a", default="authorization.yml", show_default=True)
@click.option("--audit-log", default=None,
              help="Path to the audit log (default: <engagement_id>.audit.jsonl)")
def status(authorization, audit_log):
    """Show engagement status: time remaining, scope summary, audit log integrity."""
    from datetime import datetime

    from redteam_toolkit.core.audit_log import verify_log_integrity
    from redteam_toolkit.core.authorization import AuthorizationError, load_authorization

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    log_path = (
        Path(audit_log) if audit_log
        else Path(authorization).parent / f"{auth.engagement_id}.audit.jsonl"
    )

    console.print(f"[bold]Engagement:[/bold] {auth.engagement_id} ({auth.client})")

    now = datetime.now(UTC)
    if auth.is_within_window():
        remaining = auth.window.end - now
        console.print(
            f"[green]Status: ACTIVE[/green] — "
            f"{remaining.days}d {remaining.seconds // 3600}h remaining"
        )
    elif now < auth.window.start:
        until = auth.window.start - now
        console.print(
            f"[yellow]Status: NOT YET STARTED[/yellow] — begins in "
            f"{until.days}d {until.seconds // 3600}h"
        )
    else:
        console.print("[red]Status: EXPIRED[/red]")

    console.print(
        f"Scope: {len(auth.scope.targets)} target pattern(s), "
        f"{len(auth.scope.excluded_targets)} exclusion(s)"
    )
    console.print(f"Categories: {', '.join(auth.scope.allowed_categories) or 'none'}")

    if log_path.exists():
        valid, broken_line = verify_log_integrity(log_path)
        entry_count = sum(1 for line in open(log_path, encoding="utf-8") if line.strip())
        if valid:
            console.print(f"[green]Audit log: OK[/green] — {entry_count} entries, integrity verified")
        else:
            console.print(f"[red]Audit log: TAMPERED[/red] — chain broken at line {broken_line}")
    else:
        console.print("[dim]Audit log: none yet[/dim]")


@cli.command()
@click.argument("target")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml")
@click.option("--audit-log", default=None,
              help="Path to the audit log (default: <engagement_id>.audit.jsonl)")
@click.option("--modules", "-m", default=None,
              help="Comma-separated modules to run (default: all recon modules)")
@click.option("--aggressive", is_flag=True,
              help="Raise rate limits beyond the safe default. Prints a warning before running.")
def recon(target, authorization, audit_log, modules, aggressive):
    """Run reconnaissance modules against TARGET.

    Every module call goes through the engagement's scope gate first — a
    target outside the authorized scope or time window is refused and
    logged, not silently skipped.
    """
    from redteam_toolkit.core.authorization import AuthorizationError
    from redteam_toolkit.core.engagement import Engagement
    from redteam_toolkit.recon.active_dns import (
        AGGRESSIVE_RATE_PER_SECOND as DNS_AGGRESSIVE,
    )
    from redteam_toolkit.recon.active_dns import (
        SAFE_RATE_PER_SECOND as DNS_SAFE,
    )
    from redteam_toolkit.recon.active_dns import ActiveDNSModule, ZoneTransferModule
    from redteam_toolkit.recon.endpoint_discovery import (
        AGGRESSIVE_RATE_PER_SECOND as ENDPOINT_AGGRESSIVE,
    )
    from redteam_toolkit.recon.endpoint_discovery import (
        SAFE_RATE_PER_SECOND as ENDPOINT_SAFE,
    )
    from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule
    from redteam_toolkit.recon.fingerprint import FingerprintModule
    from redteam_toolkit.recon.passive_dns import PassiveDNSModule
    from redteam_toolkit.recon.port_scanner import (
        AGGRESSIVE_RATE_PER_SECOND as PORT_AGGRESSIVE,
    )
    from redteam_toolkit.recon.port_scanner import (
        SAFE_RATE_PER_SECOND as PORT_SAFE,
    )
    from redteam_toolkit.recon.port_scanner import PortScannerModule
    from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

    try:
        eng = Engagement.load(authorization, audit_log)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    available = {
        "port_scanner": lambda: PortScannerModule(
            eng, rate_per_second=PORT_AGGRESSIVE if aggressive else PORT_SAFE,
        ),
        "fingerprint": lambda: FingerprintModule(eng),
        "passive_dns": lambda: PassiveDNSModule(eng),
        "active_dns": lambda: ActiveDNSModule(
            eng, rate_per_second=DNS_AGGRESSIVE if aggressive else DNS_SAFE,
        ),
        "zone_transfer": lambda: ZoneTransferModule(eng),
        "web_fingerprint": lambda: WebFingerprintModule(eng),
        "endpoint_discovery": lambda: EndpointDiscoveryModule(
            eng, rate_per_second=ENDPOINT_AGGRESSIVE if aggressive else ENDPOINT_SAFE,
        ),
    }

    selected = [m.strip() for m in modules.split(",")] if modules else list(available.keys())

    console.print()
    console.rule(f"[bold cyan]🎯 Recon: {target}[/bold cyan]")
    if aggressive:
        console.print("\n[yellow]⚠ --aggressive: rate limits raised above the safe default.[/yellow]")
    console.print()

    all_findings = []
    for name in selected:
        if name not in available:
            console.print(f"[red]Unknown module: {name}[/red]")
            continue
        result = available[name]().run(target)
        if result.error:
            console.print(f"[yellow]⚠[/yellow] {name}: {result.error}")
        else:
            console.print(
                f"[green]✔[/green] {name}: {len(result.findings)} finding(s) "
                f"({result.duration_ms:.0f}ms)"
            )
        all_findings.extend(result.findings)

    if all_findings:
        t = Table(box=box.SIMPLE_HEAD, show_lines=True)
        t.add_column("Module")
        t.add_column("Title", overflow="fold")
        t.add_column("Severity")
        for f in all_findings:
            t.add_row(f.module, f.title, f.severity.value)
        console.print()
        console.print(t)
    else:
        console.print("\n[dim]No findings.[/dim]")


def main():
    cli()


if __name__ == "__main__":
    main()
