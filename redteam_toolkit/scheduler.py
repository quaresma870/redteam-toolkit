"""
Scheduler — runs a recurring `recon` pass on a cron schedule.

Deliberately recon-only. This project's top-level CLI docstring states
"There is deliberately no schedule command anywhere in this tool -- every
run is a single, attended, deliberate action" -- true and important for
vuln-id and especially active, which requires an explicit --confirm on
every single invocation precisely because probing a live target with real
payloads (SQL injection attempts, XSS payloads, SSRF canary triggers)
isn't something that should ever run unattended on a timer: an
authorization that's technically still within its time window doesn't
mean anyone is still watching what a stale cron job might do to a live
system months later.

recon's own modules don't carry that risk the same way -- they're either
fully passive (passive_dns, fingerprint reading a banner) or the same
bounded, well-understood reconnaissance techniques (port_scanner,
endpoint_discovery) already considered safe enough to run without
--confirm even in the ordinary, non-scheduled case. Extending unattended
automation to vuln-id or active would directly contradict the existing,
deliberate safety principle for a tool whose targets are real, live
external systems -- not source code, which is what secureaudit's own
`schedule` command (whose cron-parsing pattern this ports) operates
against instead.

The authorization window is re-checked before every single scheduled
run, not just once at startup -- and if it's expired, the scheduler
STOPS entirely (not just skips one tick and keeps polling forever
against an authorization that will never become valid again).
"""

from __future__ import annotations

import time

from rich.console import Console

console = Console()


def _parse_cron(cron_expr: str, job_fn):
    """Same minimal 5-field cron subset secureaudit's scheduler already
    supports (*/N minutes, */N hours, daily HH:MM, weekly on a given
    weekday HH:MM) -- ported directly rather than reinvented, since it's
    the exact same underlying `schedule` library and the exact same
    reasonable subset of cron syntax that covers real recurring-scan
    use cases without pulling in a full croniter dependency."""
    try:
        import schedule
    except ImportError:
        raise RuntimeError("Install schedule: pip install schedule") from None

    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Need 5 cron fields, got: {cron_expr!r}")

    minute, hour, _dom, _month, _dow = parts

    try:
        if minute.startswith("*/") and hour == "*":
            interval = _parse_positive_int(minute[2:], "minute interval (the N in '*/N')")
            return schedule.every(interval).minutes.do(job_fn)
        if hour.startswith("*/") and minute == "0":
            interval = _parse_positive_int(hour[2:], "hour interval (the N in '*/N')")
            return schedule.every(interval).hours.do(job_fn)
        if minute.isdigit() and hour.isdigit():
            h, m = _parse_time_of_day(hour, minute)
            return schedule.every().day.at(f"{h:02d}:{m:02d}").do(job_fn)

        dow_map = {"0": "monday", "1": "tuesday", "2": "wednesday",
                   "3": "thursday", "4": "friday", "5": "saturday", "6": "sunday"}
        if _dow in dow_map and minute.isdigit() and hour.isdigit():
            h, m = _parse_time_of_day(hour, minute)
            return getattr(schedule.every(), dow_map[_dow]).at(f"{h:02d}:{m:02d}").do(job_fn)
    except schedule.ScheduleError as exc:
        # Belt-and-suspenders: the explicit validation above (positive
        # intervals, in-range hour/minute) already catches the specific
        # cases actually reproduced and confirmed real, but converting
        # any OTHER schedule-library error into the same ValueError type
        # here means callers only ever need to catch one exception type
        # for "this cron expression was bad," not two, even if a future
        # code path in this function bypasses the helpers above.
        raise ValueError(str(exc)) from exc

    raise ValueError(f"Unsupported cron: {cron_expr!r}")


def _parse_positive_int(raw: str, field_desc: str) -> int:
    """Validates a '*/N' interval field. Confirmed by actually
    reproducing this for real, not assumed as a risk from reading the
    code: schedule.every(0).minutes (an N of exactly 0, e.g. from a
    typo'd '*/0 * * * *') doesn't raise — it hangs the process
    indefinitely inside the schedule library's own internal next-run
    computation, a real denial-of-service for anyone who fat-fingers
    a zero into the interval. Rejecting N<1 here, before the value
    ever reaches schedule.every(), turns that hang into an immediate,
    clear error instead."""
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"Invalid {field_desc}: {raw!r} is not an integer") from None
    if value < 1:
        raise ValueError(
            f"Invalid {field_desc}: {value} — must be a positive integer "
            f"(an interval of 0 or less would never (or always) fire)"
        )
    return value


def _parse_time_of_day(hour: str, minute: str) -> tuple[int, int]:
    """Validates an HH:MM time-of-day pair is in range. Confirmed by
    actually reproducing this for real: an out-of-range value (e.g.
    hour=25 or minute=60) is NOT caught by isdigit() (both are valid
    digit strings), and previously reached the `schedule` library's own
    at() call, which raises schedule.ScheduleValueError -- a type this
    module's own callers weren't catching (only plain ValueError),
    producing a raw, unhandled traceback instead of a clean CLI error
    message. Validating the range here means the error is both caught
    (a plain ValueError, consistent with every other error this
    function raises) and clearer (names the actual out-of-range field,
    rather than the library's generic 'Invalid time format')."""
    h, m = int(hour), int(minute)
    if not (0 <= h <= 23):
        raise ValueError(f"Invalid hour: {h} — must be 0-23")
    if not (0 <= m <= 59):
        raise ValueError(f"Invalid minute: {m} — must be 0-59")
    return h, m


# The only modules `schedule` will run -- recon's own registry, kept as a
# separate, explicit list here (not imported from cli.py's own recon
# registry) so this file's scope stays obviously self-contained and
# auditable: anyone reading this module alone can see exactly what
# schedule can and cannot run, without cross-referencing cli.py.
def _available_recon_modules(eng):
    from redteam_toolkit.recon.active_dns import ActiveDNSModule, ZoneTransferModule
    from redteam_toolkit.recon.endpoint_discovery import EndpointDiscoveryModule
    from redteam_toolkit.recon.fingerprint import FingerprintModule
    from redteam_toolkit.recon.passive_dns import PassiveDNSModule
    from redteam_toolkit.recon.port_scanner import PortScannerModule
    from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule
    from redteam_toolkit.recon.web_fingerprint import WebFingerprintModule

    return {
        "port_scanner": lambda: PortScannerModule(eng),
        "fingerprint": lambda: FingerprintModule(eng),
        "passive_dns": lambda: PassiveDNSModule(eng),
        "active_dns": lambda: ActiveDNSModule(eng),
        "zone_transfer": lambda: ZoneTransferModule(eng),
        "web_fingerprint": lambda: WebFingerprintModule(eng),
        "subdomain_takeover": lambda: SubdomainTakeoverModule(eng),
        "endpoint_discovery": lambda: EndpointDiscoveryModule(eng),
    }


def run_schedule(
    eng,
    targets: list[str],
    modules: list[str] | None,
    cron_expr: str,
    db: str | None,
) -> None:
    """Runs `recon` against every target in `targets` on the given cron
    schedule. `eng` is an already-loaded Engagement — its authorization
    window is re-checked before every single scheduled tick via
    is_within_window(), not just once here at startup."""
    try:
        import schedule as schedule_lib
    except ImportError:
        console.print("[red]Install schedule: pip install schedule[/red]")
        return

    available = _available_recon_modules(eng)
    selected = modules or list(available.keys())
    for name in modules or []:
        if name not in available:
            console.print(
                f"[red]Unknown recon module: {name!r}.[/red] "
                f"Available: {', '.join(available.keys())}"
            )
            return

    run_count = [0]
    stopped = [False]

    def job():
        if not eng.authorization.is_within_window():
            console.print(
                "\n[red]✘ Authorization window has expired — stopping the scheduler.[/red]\n"
                f"[dim]Window ended: {eng.authorization.window.end.isoformat()}[/dim]\n"
            )
            stopped[0] = True
            return

        run_count[0] += 1
        console.print()
        console.rule(f"[cyan]Scheduled recon run #{run_count[0]}[/cyan]")

        for target in targets:
            console.print()
            console.rule(f"[bold cyan]🎯 {target}[/bold cyan]")
            for name in selected:
                result = available[name]().run(target)
                if result.error:
                    console.print(f"[yellow]⚠[/yellow] {name}: {result.error}")
                else:
                    console.print(
                        f"[green]✔[/green] {name}: {len(result.findings)} finding(s) "
                        f"({result.duration_ms:.0f}ms)"
                    )
                if db:
                    from redteam_toolkit.core.history import save_module_result
                    save_module_result(db, eng.authorization.engagement_id, target, result)

        if db:
            console.print(f"\n[dim]Results saved to {db}.[/dim]")

    _parse_cron(cron_expr, job)
    console.print(
        f"\n[bold cyan]⏱  redteam-toolkit scheduled (recon only):[/bold cyan] "
        f"[green]{cron_expr}[/green] — Ctrl+C to stop\n"
    )
    job()  # run immediately on start — the same "runs now, then on the
    # configured cadence" behavior secureaudit's own schedule command has.

    try:
        while not stopped[0]:
            schedule_lib.run_pending()
            time.sleep(30)
    except KeyboardInterrupt:
        console.print("\n[cyan]Scheduler stopped.[/cyan]")
