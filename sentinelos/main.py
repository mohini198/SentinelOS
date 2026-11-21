"""
SentinelOS — Typer CLI entry point.
(Stubbed for Step 1; will grow in later steps.)
"""

import typer

app = typer.Typer(
    name="sentinelos",
    help="SentinelOS: AI-assisted Linux failure diagnosis and safe remediation.",
    add_completion=False,
)


@app.command()
def version():
    """Print the SentinelOS version."""
    from sentinelos import __version__
    typer.echo(f"SentinelOS v{__version__}")


@app.command()
def audit_verify(
    db: str = typer.Option("sentinelos.db", "--db", help="Path to the SQLite database"),
):
    """Verify the integrity of the audit log hash chain."""
    from sentinelos.audit import AuditLog

    log = AuditLog(db_path=db)
    ok, msg = log.verify_chain()
    color = typer.colors.GREEN if ok else typer.colors.RED
    typer.secho(f"[{'OK' if ok else 'FAIL'}] {msg}", fg=color, bold=True)
    raise SystemExit(0 if ok else 1)

@app.command()
def monitor(
    interval: float = typer.Option(2.0, help="Seconds between checks"),
    cooldown: float = typer.Option(60.0, help="Seconds before repeating the same incident"),
    once: bool = typer.Option(False, help="Run a single check and exit"),
    no_logs: bool = typer.Option(False, help="Skip journalctl/dmesg collection"),
):
    """Poll the system and print detected incidents."""
    from sentinelos.monitor_loop import run_monitor
    run_monitor(interval, cooldown, once, no_logs)

@app.command()
def act(
    action_id: str,
    param: list[str] = typer.Option([], "--param", "-p", help="key=value, repeatable"),
    execute: bool = typer.Option(False, "--execute", help="really run it (also needs SENTINEL_DRY_RUN=false)"),
):
    """Developer tool: try one allowlisted action (dry-run by default)."""
    from sentinelos.actions import run_action
    from sentinelos.config import settings
    params = {}
    for kv in param:
        k, _, v = kv.partition("=")
        params[k] = int(v) if v.lstrip("-").isdigit() else v
    dry = settings.dry_run or not execute
    r = run_action(action_id, params, dry_run=dry)
    typer.echo(f"[{r.outcome}] {r.action_id} (risk {r.risk}): {r.detail}")
    
def _db(db: str) -> str:
    from sentinelos.config import settings
    return db or str(settings.db_path)


@app.command()
def incidents(limit: int = typer.Option(15, help="How many to show"),
              db: str = typer.Option("", "--db", help="SQLite path")):
    """List recent incidents."""
    from sentinelos.approval import open_session, recent_incidents
    with open_session(_db(db)) as s:
        rows = recent_incidents(s, limit)
    if not rows:
        typer.echo("no incidents")
    for i in rows:
        typer.echo(f"#{i.id:<4} {i.uuid[:8]}  {i.severity:<8} {i.state:<17} {i.fault_type:<18} {i.summary[:55]}")


@app.command()
def review(ref: str, db: str = typer.Option("", "--db")):
    """Show diagnosis and proposed fixes (with dry-run preview) for an incident."""
    from sentinelos.approval import build_review, find_incident, open_session, render_review
    with open_session(_db(db)) as s:
        inc = find_incident(s, ref)
    if inc is None:
        typer.secho("incident not found", fg=typer.colors.RED)
        raise typer.Exit(1)
    diag, props = build_review(inc)
    typer.echo(render_review(inc, diag, props))


@app.command()
def approve(ref: str, n: int,
            by: str = typer.Option("", "--by", help="your name (default: OS user)"),
            execute: bool = typer.Option(False, "--execute", help="really run it (needs SENTINEL_DRY_RUN=false)"),
            confirm: str = typer.Option("", "--confirm", help="typed confirmation for High-risk actions"),
            yes: bool = typer.Option(False, "--yes", help="skip the yes/no question"),
            db: str = typer.Option("", "--db")):
    """Approve proposal N of an incident. Dry-run unless --execute."""
    import getpass
    from sentinelos.approval import build_review, find_incident, open_session
    from sentinelos.config import settings
    from sentinelos.executor import Executor
    path = _db(db)
    with open_session(path) as s:
        inc = find_incident(s, ref)
    if inc is None:
        typer.secho("incident not found", fg=typer.colors.RED)
        raise typer.Exit(1)
    _, props = build_review(inc)
    if not 1 <= n <= len(props):
        typer.secho(f"choose a proposal number from 1 to {len(props)}", fg=typer.colors.RED)
        raise typer.Exit(1)
    p = props[n - 1]
    shown = {k: v for k, v in p.params.items() if k != "reason"}
    typer.echo(f"Proposal {n}: {p.action_id} {shown} (risk {p.risk})")
    real = execute
    if real and settings.dry_run:
        typer.secho("SENTINEL_DRY_RUN is true, so this runs as a dry-run only.", fg=typer.colors.YELLOW)
        real = False
    if real:
        if not yes:
            typer.confirm("Run this for real?", abort=True)
        if p.risk == "High" and not confirm:
            confirm = typer.prompt(f"High risk. Type '{p.action_id}' to confirm")
    res = Executor(path).execute(inc, p, by or getpass.getuser(), confirm or None, real=real)
    color = {"SUCCESS": typer.colors.GREEN, "DRY_RUN": typer.colors.CYAN}.get(res.outcome, typer.colors.RED)
    typer.secho(f"[{res.outcome}] {res.detail}", fg=color, bold=True)
    if res.verdict:
        typer.echo(f"verification: {res.verdict} (before={res.before}, after={res.after})")


@app.command()
def reject(ref: str, n: int, by: str = typer.Option("", "--by"),
           reason: str = typer.Option("", "--reason"), db: str = typer.Option("", "--db")):
    """Reject proposal N (recorded in the audit log)."""
    import getpass
    from sentinelos.approval import build_review, find_incident, open_session
    from sentinelos.executor import Executor
    path = _db(db)
    with open_session(path) as s:
        inc = find_incident(s, ref)
    if inc is None:
        typer.secho("incident not found", fg=typer.colors.RED)
        raise typer.Exit(1)
    _, props = build_review(inc)
    if not 1 <= n <= len(props):
        raise typer.Exit(1)
    Executor(path).reject(inc, props[n - 1], by or getpass.getuser(), reason)
    typer.echo("rejected and logged")


@app.command()
def audit_show(limit: int = typer.Option(15), db: str = typer.Option("", "--db")):
    """Show recent audit entries and verify the hash chain."""
    from sentinelos.audit import AuditLog
    log = AuditLog(_db(db))
    for e in reversed(log.get_entries(limit)):
        dry = "(dry)" if e.is_dry_run else ""
        typer.echo(f"#{e.id:<4} {e.created_at:%H:%M:%S} {e.action_id:<24} {e.risk_tier:<7} "
                   f"{e.outcome:<11} by={e.approved_by} {dry} {(e.outcome_detail or '')[:45]}")
    ok, msg = log.verify_chain()
    typer.secho(f"chain: {msg}", fg=typer.colors.GREEN if ok else typer.colors.RED)

if __name__ == "__main__":
    app()
