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
    
if __name__ == "__main__":
    app()
