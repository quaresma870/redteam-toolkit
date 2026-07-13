"""
redteam-toolkit CLI — entry point.

Every command other than `init` requires a validated authorization.yml.
`schedule` is the only command that runs unattended on a recurring
cadence, and it is deliberately recon-only — vuln-id and active always
require a single, attended, deliberate invocation (active additionally
requires --confirm every single time). See schedule()'s own docstring
for why that boundary exists and isn't crossed.
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


def _resolve_targets(targets: tuple[str, ...], targets_file: str | None) -> list[str]:
    """Combines targets given directly on the command line with any read
    from --targets-file (one per line; blank lines and lines starting
    with # ignored), deduplicated while preserving first-seen order so
    output stays predictable run to run. Used identically by recon,
    vuln-id, and active so all three batch the same way rather than each
    growing its own slightly-different variant."""
    resolved: list[str] = list(targets)
    if targets_file:
        for line in Path(targets_file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                resolved.append(line)
    seen: set[str] = set()
    deduped = []
    for t in resolved:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def _parse_session_headers(raw: tuple[str, ...]) -> dict[str, str]:
    """Parses --session-header 'Name: Value' strings into a dict. Used by
    recon/vuln-id/active so a module's HTTP-based fetch can attach session
    credentials (a cookie, a bearer token) to outgoing requests — for
    scanning targets behind a login wall. These are credentials: never
    echoed back to the console, never written to the audit log or any
    report — see Engagement.auth_headers() and SessionAuth's redacted
    repr/str for where that's actually enforced."""
    headers: dict[str, str] = {}
    for item in raw:
        if ":" not in item:
            raise click.BadParameter(
                f"--session-header must be 'Name: Value', got: {item!r}"
            )
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def _register_engagement(db_path: str, eng) -> None:
    from redteam_toolkit.core.history import register_engagement

    auth = eng.authorization
    register_engagement(
        db_path,
        engagement_id=auth.engagement_id,
        client=auth.client,
        authorized_by=auth.authorized_by,
        target_scope=auth.scope.targets,
        window_start=auth.window.start.isoformat(),
        window_end=auth.window.end.isoformat(),
    )


def _save_module_result(db_path: str, eng, target: str, result) -> None:
    from redteam_toolkit.core.history import save_module_result

    save_module_result(db_path, eng.authorization.engagement_id, target, result)


def _print_diff(result) -> None:
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    console.print()
    console.rule(f"[bold cyan]Diff: run #{result.run1_id} → run #{result.run2_id}[/bold cyan]")
    console.print()

    if result.new:
        t = Table(title=f"🆕 New findings ({len(result.new)})", box=box.SIMPLE_HEAD, border_style="red")
        t.add_column("Severity")
        t.add_column("Module")
        t.add_column("Title", overflow="fold")
        t.add_column("Target", overflow="fold")
        t.add_column("Status")
        for f in sorted(result.new, key=lambda x: sev_order.index(x["severity"])):
            t.add_row(f["severity"], f["module"], f["title"], f.get("target") or "", f.get("status", "open"))
        console.print(t)
    else:
        console.print("[green]No new findings.[/green]")

    if result.resolved:
        t = Table(title=f"✅ Resolved findings ({len(result.resolved)})", box=box.SIMPLE_HEAD, border_style="green")
        t.add_column("Severity")
        t.add_column("Module")
        t.add_column("Title", overflow="fold")
        t.add_column("Target", overflow="fold")
        t.add_column("Status")
        for f in sorted(result.resolved, key=lambda x: sev_order.index(x["severity"])):
            t.add_row(f["severity"], f["module"], f["title"], f.get("target") or "", f.get("status", "open"))
        console.print(t)

    console.print(f"\n[dim]{result.unchanged_count} unchanged finding(s).[/dim]")

    if result.has_new_regression:
        console.print("\n[bold red]✘ Regression: new CRITICAL/HIGH findings introduced.[/bold red]\n")
    else:
        console.print("\n[green]✔ No regression.[/green]\n")


try:
    __version__ = importlib.metadata.version("redteam-toolkit")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0+dev"

_TEMPLATE = """# redteam-toolkit authorization — fill in EVERY field before use.
# This file is the only thing that permits any scan to run.
# Read https://github.com/quaresma870/redteam-toolkit/blob/main/docs/legal-and-ethics.md before completing it.
# (docs/ is a repo-only directory, not bundled into the pip package — this
# link works regardless of how you installed this tool.)

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
    https://github.com/quaresma870/redteam-toolkit/blob/main/docs/legal-and-ethics.md
    before your first engagement (docs/ isn't bundled into the pip
    package — this link works regardless of how you installed this tool).
    """


_TEMPLATE_CHOICES = ["web-app", "network", "internal-redteam"]
_TEMPLATE_FILENAMES = {
    "web-app": "authorization-web-app.yml.example",
    "network": "authorization-network.yml.example",
    "internal-redteam": "authorization-internal-redteam.yml.example",
}


@cli.command()
@click.option("--output", "-o", default="authorization.yml", show_default=True,
              help="Path to write the authorization template.")
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
@click.option("--template", type=click.Choice(_TEMPLATE_CHOICES), default=None,
              help="Start from an engagement-type template (web-app, network, internal-redteam) "
                   "instead of the generic one. Still requires manual completion — no template "
                   "pre-fills scope, dates, or the confirmation phrase.")
def init(output, force, template):
    """Create an authorization.yml template.

    Every field still requires manual completion — this never auto-fills
    scope, dates, or the confirmation phrase.
    """
    path = Path(output)
    if path.exists() and not force:
        console.print(f"[red]{path} already exists.[/red] Use --force to overwrite.")
        sys.exit(1)

    if template:
        import importlib.resources
        filename = _TEMPLATE_FILENAMES[template]
        content = importlib.resources.files("redteam_toolkit.templates").joinpath(filename).read_text()
        label = f" ({template} template)"
    else:
        content = _TEMPLATE
        label = ""

    path.write_text(content, encoding="utf-8")
    console.print(f"[green]✔[/green] Template written{label}: [bold]{path}[/bold]")
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

    from redteam_toolkit.core.rate_limit import DEFAULT_MAX_PER_SECOND, DEFAULT_MAX_TOTAL_REQUESTS
    rl = auth.rate_limits
    max_total = rl.max_total_requests if rl else DEFAULT_MAX_TOTAL_REQUESTS
    max_per_sec = rl.max_per_second if rl else DEFAULT_MAX_PER_SECOND
    source = "configured in authorization.yml" if rl else "default"
    console.print(
        f"Rate budget: {max_total} request(s)/session, {max_per_sec}/sec ceiling ({source})"
    )

    if log_path.exists():
        valid, broken_line, entry_count = verify_log_integrity(log_path)
        if valid:
            console.print(
                f"[green]Audit log: OK[/green] — {entry_count} entries, integrity verified "
                f"[dim](hash-chaining detects edits/reordering, but not truncation of the most "
                f"recent entries — see README)[/dim]"
            )
        else:
            console.print(
                f"[red]Audit log: TAMPERED[/red] — chain broken at line {broken_line} "
                f"({entry_count} entries verified before the break)"
            )
    else:
        console.print("[dim]Audit log: none yet[/dim]")


@cli.command()
@click.argument("targets", nargs=-1, required=False)
@click.option("--targets-file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="File with one target per line (# comments and blank lines ignored). "
                   "Combined with any TARGETS given directly.")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml")
@click.option("--audit-log", default=None,
              help="Path to the audit log (default: <engagement_id>.audit.jsonl)")
@click.option("--modules", "-m", default=None,
              help="Comma-separated modules to run (default: all recon modules)")
@click.option("--aggressive", is_flag=True,
              help="Raise rate limits beyond the safe default. Prints a warning before running.")
@click.option("--session-header", multiple=True,
              help="'Name: Value' header (e.g. a session cookie) to attach to every HTTP request "
                   "this run makes — for scanning targets behind a login wall. Repeatable. "
                   "Merges with (and overrides on conflict) authorization.yml's session_auth.headers.")
@click.option("--db", default=None,
              help="SQLite database to persist results for the 'report' command and dashboard.")
def recon(targets, targets_file, authorization, audit_log, modules, aggressive, session_header, db):
    """Run reconnaissance modules against one or more TARGETS.

    Accepts multiple targets directly (recon a.example.com b.example.com)
    and/or via --targets-file. Each target is scoped, rate-limited, and
    scanned independently and in sequence — never in parallel, since
    rate limiting and scope checking are deliberately per-target and
    sequential, not a shared budget split across concurrent targets.

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
    from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule
    from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

    try:
        eng = Engagement.load(authorization, audit_log, extra_session_headers=_parse_session_headers(session_header))
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    resolved_targets = _resolve_targets(targets, targets_file)
    if not resolved_targets:
        console.print("[red]✘ No targets given — pass one or more TARGETS or --targets-file.[/red]")
        sys.exit(1)

    if db:
        _register_engagement(db, eng)

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
        "subdomain_takeover": lambda: SubdomainTakeoverModule(eng),
        "endpoint_discovery": lambda: EndpointDiscoveryModule(
            eng, rate_per_second=ENDPOINT_AGGRESSIVE if aggressive else ENDPOINT_SAFE,
        ),
    }

    selected = [m.strip() for m in modules.split(",")] if modules else list(available.keys())

    if aggressive:
        console.print("\n[yellow]⚠ --aggressive: rate limits raised above the safe default.[/yellow]")
    if len(resolved_targets) > 1:
        console.print(f"\n[dim]{len(resolved_targets)} targets queued, run sequentially (not in parallel).[/dim]")

    grand_total_findings = []
    for target in resolved_targets:
        console.print()
        console.rule(f"[bold cyan]🎯 Recon: {target}[/bold cyan]")
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
            if db:
                _save_module_result(db, eng, target, result)

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

        grand_total_findings.extend(all_findings)

    if len(resolved_targets) > 1:
        console.print(f"\n[bold]{len(resolved_targets)} targets, {len(grand_total_findings)} total finding(s).[/bold]")

    if db:
        console.print(f"\n[dim]Results saved to {db} — run 'redteam-toolkit report' to generate a full report.[/dim]")


@cli.command(name="vuln-id")
@click.argument("targets", nargs=-1, required=False)
@click.option("--targets-file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="File with one target per line (# comments and blank lines ignored). "
                   "Combined with any TARGETS given directly.")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml")
@click.option("--audit-log", default=None,
              help="Path to the audit log (default: <engagement_id>.audit.jsonl)")
@click.option("--modules", "-m", default=None,
              help="Comma-separated modules to run (default: all vuln-id modules except default_credentials)")
@click.option("--check-default-creds", is_flag=True,
              help="Opt in to the default-credential spot-check — off by default even if requested via --modules.")
@click.option("--tls-port", default=443, show_default=True, help="Port to use for the TLS analyzer.")
@click.option("--session-header", multiple=True,
              help="'Name: Value' header (e.g. a session cookie) to attach to every HTTP request "
                   "this run makes — for scanning targets behind a login wall. Repeatable. "
                   "Merges with (and overrides on conflict) authorization.yml's session_auth.headers.")
@click.option("--db", default=None,
              help="SQLite database to persist results for the 'report' command and dashboard.")
def vuln_id(targets, targets_file, authorization, audit_log, modules, check_default_creds, tls_port, session_header, db):
    """Run vulnerability identification modules against one or more TARGETS.
    Read-only — no exploitation, no credential brute-forcing.

    Accepts multiple targets directly and/or via --targets-file, scanned
    independently and in sequence — see `recon --help` for the same
    sequential-not-parallel rationale, which applies here identically.
    """
    from redteam_toolkit.core.authorization import AuthorizationError
    from redteam_toolkit.core.cvss import ensure_cvss_score
    from redteam_toolkit.core.engagement import Engagement
    from redteam_toolkit.vuln_id.cve_correlation import CVECorrelationModule
    from redteam_toolkit.vuln_id.default_credentials import DefaultCredentialModule
    from redteam_toolkit.vuln_id.http_posture import HTTPPostureModule
    from redteam_toolkit.vuln_id.tls_analyzer import TLSAnalyzerModule

    try:
        eng = Engagement.load(authorization, audit_log, extra_session_headers=_parse_session_headers(session_header))
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    resolved_targets = _resolve_targets(targets, targets_file)
    if not resolved_targets:
        console.print("[red]✘ No targets given — pass one or more TARGETS or --targets-file.[/red]")
        sys.exit(1)

    if db:
        _register_engagement(db, eng)

    available = {
        "cve_correlation": lambda: CVECorrelationModule(eng),
        "tls_analyzer": lambda: TLSAnalyzerModule(eng, port=tls_port),
        "http_posture": lambda: HTTPPostureModule(eng),
        "default_credentials": lambda: DefaultCredentialModule(eng),
    }

    # default_credentials is never included unless explicitly named — being
    # 'vuln-id' authorized is not the same as opting into this specific check.
    default_selection = [n for n in available if n != "default_credentials"]
    selected = [m.strip() for m in modules.split(",")] if modules else default_selection

    if len(resolved_targets) > 1:
        console.print(f"\n[dim]{len(resolved_targets)} targets queued, run sequentially (not in parallel).[/dim]")

    grand_total_findings = []
    for target in resolved_targets:
        console.print()
        console.rule(f"[bold cyan]🔍 Vulnerability identification: {target}[/bold cyan]")
        console.print()

        all_findings = []
        for name in selected:
            if name not in available:
                console.print(f"[red]Unknown module: {name}[/red]")
                continue
            module = available[name]()
            if name == "default_credentials":
                result = module.run(target, opt_in=check_default_creds)
            else:
                result = module.run(target)

            if result.error:
                console.print(f"[yellow]⚠[/yellow] {name}: {result.error}")
            else:
                console.print(
                    f"[green]✔[/green] {name}: {len(result.findings)} finding(s) "
                    f"({result.duration_ms:.0f}ms)"
                )
            for f in result.findings:
                ensure_cvss_score(f)
            all_findings.extend(result.findings)
            if db:
                _save_module_result(db, eng, target, result)

        if all_findings:
            t = Table(box=box.SIMPLE_HEAD, show_lines=True)
            t.add_column("Module")
            t.add_column("Title", overflow="fold")
            t.add_column("Severity")
            t.add_column("CVSS", justify="right")
            for f in all_findings:
                t.add_row(f.module, f.title, f.severity.value, f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—")
            console.print()
            console.print(t)
        else:
            console.print("\n[dim]No findings.[/dim]")

        grand_total_findings.extend(all_findings)

    if len(resolved_targets) > 1:
        console.print(f"\n[bold]{len(resolved_targets)} targets, {len(grand_total_findings)} total finding(s).[/bold]")

    if db:
        console.print(f"\n[dim]Results saved to {db} — run 'redteam-toolkit report' to generate a full report.[/dim]")


@cli.command()
@click.argument("targets", nargs=-1, required=False)
@click.option("--targets-file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="File with one target per line (# comments and blank lines ignored). "
                   "Combined with any TARGETS given directly.")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml")
@click.option("--audit-log", default=None,
              help="Path to the audit log (default: <engagement_id>.audit.jsonl)")
@click.option("--modules", "-m", default=None,
              help="Comma-separated modules to run (default: all active-tier modules)")
@click.option("--confirm", required=True,
              help="Type the exact engagement_id from authorization.yml to confirm intent "
                   "to run active-tier checks. Required every invocation — not a boolean flag.")
@click.option("--canary-host", default="127.0.0.1", show_default=True,
              help="Host to bind the local SSRF canary listener to.")
@click.option("--session-header", multiple=True,
              help="'Name: Value' header (e.g. a session cookie) to attach to every HTTP request "
                   "this run makes — for scanning targets behind a login wall. Repeatable. "
                   "Merges with (and overrides on conflict) authorization.yml's session_auth.headers.")
@click.option("--db", default=None,
              help="SQLite database to persist results for the 'report' command and dashboard.")
def active(targets, targets_file, authorization, audit_log, modules, confirm, canary_host, session_header, db):
    """Run active-tier detection modules against one or more TARGETS.

    Non-destructive confirmation only — never exploitation. Requires
    'active' in authorization.yml's allowed_categories AND typing the exact
    engagement ID via --confirm, every time this command runs.

    Accepts multiple targets directly and/or via --targets-file, scanned
    independently and in sequence (see `recon --help`) — the canary
    listener is bound once and shared across all of them, since it's a
    generic local listener, not target-specific.
    """
    from redteam_toolkit.active.canary import LocalCanaryListener
    from redteam_toolkit.active.open_redirect import OpenRedirectModule
    from redteam_toolkit.active.path_traversal import PathTraversalModule
    from redteam_toolkit.active.sqli import SQLInjectionModule
    from redteam_toolkit.active.ssrf import SSRFDetectionModule
    from redteam_toolkit.active.xss import XSSDetectionModule
    from redteam_toolkit.core.authorization import AuthorizationError
    from redteam_toolkit.core.engagement import Engagement, ScopeViolation

    try:
        eng = Engagement.load(authorization, audit_log, extra_session_headers=_parse_session_headers(session_header))
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    resolved_targets = _resolve_targets(targets, targets_file)
    if not resolved_targets:
        console.print("[red]✘ No targets given — pass one or more TARGETS or --targets-file.[/red]")
        sys.exit(1)

    try:
        eng.confirm_active_tier(confirm)
    except ScopeViolation as exc:
        console.print(f"[red]✘ Active-tier not confirmed:[/red] {exc}")
        sys.exit(1)

    console.print("[green]✔[/green] Active-tier confirmed for this session.\n")

    if db:
        _register_engagement(db, eng)

    if len(resolved_targets) > 1:
        console.print(f"[dim]{len(resolved_targets)} targets queued, run sequentially (not in parallel).[/dim]\n")

    canary = LocalCanaryListener(host=canary_host)
    try:
        available = {
            "sqli_detection": lambda: SQLInjectionModule(eng),
            "xss_detection": lambda: XSSDetectionModule(eng),
            "open_redirect_detection": lambda: OpenRedirectModule(eng),
            "ssrf_detection": lambda: SSRFDetectionModule(eng, canary_listener=canary),
            "path_traversal_detection": lambda: PathTraversalModule(eng),
        }
        selected = [m.strip() for m in modules.split(",")] if modules else list(available.keys())

        grand_total_findings = []
        for target in resolved_targets:
            console.print()
            console.rule(f"[bold red]⚡ Active detection: {target}[/bold red]")
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
                if db:
                    _save_module_result(db, eng, target, result)

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

            grand_total_findings.extend(all_findings)

        if len(resolved_targets) > 1:
            console.print(f"\n[bold]{len(resolved_targets)} targets, {len(grand_total_findings)} total finding(s).[/bold]")

        if db:
            console.print(f"\n[dim]Results saved to {db} — run 'redteam-toolkit report' to generate a full report.[/dim]")
    finally:
        canary.shutdown()


@cli.command()
@click.argument("targets", nargs=-1, required=False)
@click.option("--targets-file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="File with one target per line (# comments and blank lines ignored). "
                   "Combined with any TARGETS given directly.")
@click.option("--cron", required=True,
              help="5-field cron expression (minute hour day month weekday). Supports "
                   "'*/N * * * *' (every N minutes), '0 */N * * *' (every N hours), "
                   "'M H * * *' (daily at H:M), and 'M H * * D' (weekly on weekday D, 0=Monday).")
@click.option("--modules", "-m", default=None,
              help="Comma-separated recon modules (default: all recon modules). "
                   "vuln-id and active tiers are NOT available via schedule.")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml")
@click.option("--audit-log", default=None,
              help="Path to the audit log (default: <engagement_id>.audit.jsonl)")
@click.option("--session-header", multiple=True,
              help="'Name: Value' header (e.g. a session cookie) to attach to every HTTP request "
                   "this scheduler makes. Repeatable.")
@click.option("--db", default=None,
              help="SQLite database to persist each scheduled run's results.")
def schedule(targets, targets_file, cron, modules, authorization, audit_log, session_header, db):
    """Run `recon` on a recurring cron schedule — deliberately recon-only.

    vuln-id and active are NOT available here, on purpose: this project's
    active tier requires an explicit --confirm on every single invocation
    precisely because probing a live target with real payloads (SQL
    injection attempts, XSS payloads, SSRF canary triggers) isn't
    something that should ever run unattended on a timer. An
    authorization that's technically still within its time window doesn't
    mean anyone is still watching what a stale cron job might do to a
    live system months later. recon's own modules don't carry that risk
    the same way — they're either fully passive or the same bounded
    techniques already considered safe enough to run without --confirm
    even in the ordinary, non-scheduled case.

    The authorization window is re-checked before every single scheduled
    run, not just once at startup — if it's expired, the scheduler stops
    entirely rather than silently polling forever against an
    authorization that will never become valid again.

    Examples:
      redteam-toolkit schedule app.acme-staging.com --cron "0 6 * * 1" --db engagements.db
      redteam-toolkit schedule --targets-file targets.txt --cron "*/30 * * * *" \\
        --modules subdomain_takeover --db engagements.db
    """
    from redteam_toolkit.core.authorization import AuthorizationError
    from redteam_toolkit.core.engagement import Engagement
    from redteam_toolkit.scheduler import run_schedule

    try:
        eng = Engagement.load(authorization, audit_log, extra_session_headers=_parse_session_headers(session_header))
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    resolved_targets = _resolve_targets(targets, targets_file)
    if not resolved_targets:
        console.print("[red]✘ No targets given — pass one or more TARGETS or --targets-file.[/red]")
        sys.exit(1)

    if not eng.authorization.is_within_window():
        console.print("[red]✘ Authorization window is not currently active — refusing to start.[/red]")
        sys.exit(1)

    selected_modules = [m.strip() for m in modules.split(",")] if modules else None

    if db:
        _register_engagement(db, eng)

    run_schedule(eng, resolved_targets, selected_modules, cron, db)


@cli.command()
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml")
@click.option("--audit-log", default=None,
              help="Path to the audit log (default: <engagement_id>.audit.jsonl)")
@click.option("--db", required=True, help="SQLite database with persisted module results.")
@click.option("--format", "fmt", type=click.Choice(["html", "pdf", "both"]), default="html", show_default=True)
@click.option("--output", "-o", default=None,
              help="Output path (default: <engagement_id>-report.<ext>)")
def report(authorization, audit_log, db, fmt, output):
    """Generate a full engagement report from everything persisted to --db
    so far (across however many separate recon/vuln-id/active invocations).
    """
    from redteam_toolkit.core.authorization import AuthorizationError, load_authorization
    from redteam_toolkit.reports.build import build_report

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    log_path = (
        Path(audit_log) if audit_log
        else Path(authorization).parent / f"{auth.engagement_id}.audit.jsonl"
    )

    rpt = build_report(auth, log_path, db)
    console.print(
        f"[bold]Engagement:[/bold] {rpt.engagement_id} — "
        f"{len(rpt.all_findings)} finding(s) across {len(rpt.module_results)} module(s)"
    )

    base = output or auth.engagement_id

    if fmt in ("html", "both"):
        from redteam_toolkit.reports.html import write_html
        html_path = base if base.endswith(".html") else f"{base}-report.html"
        write_html(rpt, html_path)
        console.print(f"[green]✔[/green] HTML report: [bold]{html_path}[/bold]")

    if fmt in ("pdf", "both"):
        from redteam_toolkit.reports.pdf import write_pdf
        pdf_path = base if base.endswith(".pdf") else f"{base}-report.pdf"
        write_pdf(rpt, pdf_path)
        console.print(f"[green]✔[/green] PDF report: [bold]{pdf_path}[/bold]")


@cli.command()
@click.argument("run1")
@click.argument("run2")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml — used to determine the engagement_id.")
@click.option("--db", required=True, help="SQLite database with persisted history (the --db used with recon/vuln-id/active).")
@click.option("--json", "json_out", is_flag=True, help="Output as JSON instead of a table.")
def diff(run1, run2, authorization, db, json_out):
    """Compare findings between two persisted scan points for this engagement.

    RUN1 and RUN2 may be numeric module-run IDs (shown when a scan saves
    to --db), or the keywords 'latest'/'previous'. "The state as of a run"
    means, for every module that's been run for this engagement by that
    point, its most recent invocation at or before that point — so
    re-running a module and getting a clean result correctly shows its
    earlier findings as resolved, not retained forever.

    Examples:
      redteam-toolkit diff 3 7 --db engagements.db
      redteam-toolkit diff previous latest --db engagements.db
    """
    from redteam_toolkit.core.authorization import AuthorizationError, load_authorization
    from redteam_toolkit.core.diff import diff_runs, resolve_run_id

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    if not Path(db).exists():
        console.print(f"[red]✘ Database not found: {db}[/red]")
        sys.exit(1)

    try:
        id1 = resolve_run_id(db, auth.engagement_id, run1)
        id2 = resolve_run_id(db, auth.engagement_id, run2)
    except ValueError as exc:
        console.print(f"[red]✘ {exc}[/red]")
        sys.exit(1)

    result = diff_runs(db, auth.engagement_id, id1, id2)

    from redteam_toolkit.core.status import annotate_with_status
    annotate_with_status(result.new, db, auth.engagement_id)
    annotate_with_status(result.resolved, db, auth.engagement_id)

    if json_out:
        import json as _json
        # Deliberately plain print(), NOT console.print(): Rich wraps
        # text to the terminal width by default, which silently injects
        # real newline characters into the middle of long JSON string
        # values (e.g. a finding's description or evidence text) --
        # producing output that LOOKS like JSON but fails to parse,
        # confirmed by actually piping this through json.load() and
        # getting a real JSONDecodeError, not assumed as a risk from
        # reading the code. Anything piping --json into a parser (which
        # is the entire point of the flag) would have silently broken on
        # any finding with a long enough description/evidence string.
        print(_json.dumps(result.to_dict(), indent=2))
    else:
        _print_diff(result)

    if result.has_new_regression:
        sys.exit(1)


@cli.command()
@click.argument("finding_id", type=int)
@click.option("--status", "new_status", type=click.Choice(["open", "false-positive", "accepted-risk", "remediated"]),
              required=True, help="Disposition to record for this finding.")
@click.option("--reason", default=None, help="Why this disposition was chosen — shown alongside the finding in diff/report output.")
@click.option("--until", default=None, metavar="YYYY-MM-DD",
              help="Expiry date. After this date, an accepted-risk/false-positive disposition silently reverts to 'open'.")
@click.option("--db", required=True, help="SQLite database with persisted history.")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True,
              help="Path to authorization.yml — used to determine the engagement_id.")
def triage(finding_id, new_status, reason, until, db, authorization):
    """Record a disposition (false-positive / accepted-risk / remediated)
    for a specific finding, by its numeric ID (shown in `report`,
    `diff --json`, or the dashboard).

    The disposition follows the finding's stable identity (module + title
    + target) — the same identity `diff` already uses to match findings
    across re-scans — so it persists onto that same logical finding even
    after a fresh recon/vuln-id/active run gives it a brand new row ID.
    A dispositioned finding is never hidden: it still appears in `diff`
    and `report` output, just visibly marked, and a false-positive or
    accepted-risk disposition no longer counts toward `diff`'s
    regression exit code.

    Examples:
      redteam-toolkit triage 42 --status accepted-risk --reason "Client approved, ticket JIRA-123" --until 2026-12-31
      redteam-toolkit triage 42 --status remediated --reason "Patched in v2.3"
      redteam-toolkit triage 42 --status open   # revert an earlier disposition
    """
    from redteam_toolkit.core.authorization import AuthorizationError, load_authorization
    from redteam_toolkit.core.diff import row_key
    from redteam_toolkit.core.status import find_finding_by_id, set_status

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    if not Path(db).exists():
        console.print(f"[red]✘ Database not found: {db}[/red]")
        sys.exit(1)

    finding = find_finding_by_id(db, finding_id)
    if finding is None:
        console.print(f"[red]✘ No finding with id {finding_id} found in {db}.[/red]")
        sys.exit(1)

    if finding["engagement_id"] != auth.engagement_id:
        console.print(
            f"[red]✘ Finding {finding_id} belongs to engagement "
            f"'{finding['engagement_id']}', not '{auth.engagement_id}'.[/red]"
        )
        sys.exit(1)

    try:
        set_status(db, auth.engagement_id, row_key(finding), new_status, reason=reason, until=until)
    except ValueError as exc:
        console.print(f"[red]✘ {exc}[/red]")
        sys.exit(1)

    console.print(
        f"[green]✔[/green] Finding {finding_id} ([bold]{finding['title']}[/bold]) "
        f"marked [bold]{new_status}[/bold]."
    )
    if reason:
        console.print(f"  [dim]Reason: {reason}[/dim]")
    if until:
        console.print(f"  [dim]Expires: {until} (reverts to 'open' after this date)[/dim]")


@cli.command()
@click.option("--db", default="engagements.db", show_default=True,
              help="SQLite database with engagement history.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8090, show_default=True)
def serve(db, host, port):
    """Start the read-only web dashboard for engagement history.

    ⚠️ Not authenticated by default — do not expose this beyond localhost
    without putting an auth layer in front of it.
    """
    try:
        # fastapi imported here too, not left for dashboard.app's own
        # import to surface unhandled — same class of bug found and
        # fixed in the sibling secureaudit repo: if uvicorn happened to
        # be installed but fastapi wasn't, this would otherwise dump a
        # raw, unhandled ModuleNotFoundError traceback instead of the
        # same clean message below.
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        console.print("[red]Dashboard dependencies missing.[/red]")
        # Square brackets are Rich markup syntax — an unescaped
        # '[dashboard]' here gets silently stripped from the visible
        # output instead of printed literally. Same bug found and fixed
        # in secureaudit's identical message; fixed here proactively
        # rather than waiting to reproduce it separately.
        console.print("Install with: pip install 'redteam-toolkit\\[dashboard]'")
        sys.exit(1)

    from redteam_toolkit.dashboard.app import create_app

    console.print(f"[bold cyan]🎯 redteam-toolkit Dashboard[/bold cyan] → http://{host}:{port}")
    console.print("[yellow]⚠ Not authenticated — localhost only unless you add auth in front of it.[/yellow]\n")
    app = create_app(db)
    uvicorn.run(app, host=host, port=port, log_level="warning")


def main():
    cli()


if __name__ == "__main__":
    main()
