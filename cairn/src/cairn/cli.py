from pathlib import Path
import json

import click
import uvicorn

from cairn.dispatcher.logging import configure_logging
from cairn.dispatcher.scheduler.loop import DispatcherLoop
from cairn.server import db


@click.group()
def main():
    """Cairn - Fact-graph based collaborative exploration protocol."""


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=8000, show_default=True, help="Bind port")
@click.option(
    "--db-path",
    type=click.Path(),
    default=str(db.DEFAULT_DB),
    show_default=True,
    help="SQLite database path",
)
@click.option("--log-level", default="info", show_default=True, help="Uvicorn log level")
@click.option("--access-log/--no-access-log", default=True, show_default=True, help="Enable Uvicorn access log")
def serve(host: str, port: int, db_path: str, log_level: str, access_log: bool):
    """Start the Cairn API server."""
    db.configure(Path(db_path))
    from cairn.server.app import app

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level.lower(),
        access_log=access_log,
    )


@main.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Dispatcher config path",
)
@click.option("--once", is_flag=True, help="Run one scheduling iteration and exit")
@click.option(
    "--startup-healthcheck-only",
    is_flag=True,
    help="Run startup worker healthchecks and exit",
)
@click.option("--log-level", default="INFO", show_default=True, help="Log level")
def dispatch(config_path: Path, once: bool, startup_healthcheck_only: bool, log_level: str):
    """Run the Cairn dispatcher."""
    configure_logging(log_level, bare=startup_healthcheck_only)
    loop = DispatcherLoop(config_path)
    try:
        if startup_healthcheck_only:
            loop.run_startup_healthchecks_only()
            return
        loop.run(once=once)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


@main.command()
@click.option(
    "--server",
    default="http://127.0.0.1:8000",
    show_default=True,
    help="Cairn server base URL",
)
@click.option("--once", is_flag=True, help="Run one poll round and exit")
@click.option("--log-level", default="INFO", show_default=True, help="Log level")
def ctf_bridge(server: str, once: bool, log_level: str):
    """Run the CTF platform bridge."""
    configure_logging(log_level)
    from cairn.ctfbridge.bridge import CtfBridge

    bridge = CtfBridge(server)
    if once:
        bridge.run_once()
    else:
        bridge.run()


@main.group("vuln-approver")
def vuln_approver():
    """Manage database-backed vulnerability approval credentials."""


@vuln_approver.command("issue")
@click.option("--identity", required=True, help="Audited approver identity")
@click.option(
    "--role",
    type=click.Choice(["approver", "senior_approver", "admin"]),
    default="approver",
    show_default=True,
)
@click.option("--expires-in-days", type=click.IntRange(1, 3650), default=90, show_default=True)
@click.option("--issued-by", default="cli-admin", show_default=True)
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=db.DEFAULT_DB,
    show_default=True,
)
def issue_vuln_approver(
    identity: str,
    role: str,
    expires_in_days: int,
    issued_by: str,
    db_path: Path,
):
    """Issue a high-entropy API key; the plaintext is printed only once."""

    from cairn.server.vulnerability_auth import issue_vulnerability_approver_credential

    db.configure(db_path)
    try:
        with db.get_conn() as conn:
            result = issue_vulnerability_approver_credential(
                conn,
                identity=identity,
                role=role,
                expires_in_days=expires_in_days,
                issued_by=issued_by,
            )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, ensure_ascii=False, sort_keys=True))


@vuln_approver.command("list")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=db.DEFAULT_DB,
    show_default=True,
)
def list_vuln_approvers(db_path: Path):
    """List identities and credential metadata without key hashes or plaintext."""

    from cairn.server.vulnerability_auth import list_vulnerability_approvers

    db.configure(db_path)
    with db.get_conn() as conn:
        result = list_vulnerability_approvers(conn)
    click.echo(json.dumps(result, ensure_ascii=False, sort_keys=True))


@vuln_approver.command("revoke")
@click.option("--credential-id", required=True)
@click.option("--revoked-by", default="cli-admin", show_default=True)
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=db.DEFAULT_DB,
    show_default=True,
)
def revoke_vuln_approver(
    credential_id: str,
    revoked_by: str,
    db_path: Path,
):
    """Revoke one credential while preserving its audit history."""

    from cairn.server.vulnerability_auth import revoke_vulnerability_approver_credential

    db.configure(db_path)
    with db.get_conn() as conn:
        revoked = revoke_vulnerability_approver_credential(
            conn, credential_id, revoked_by=revoked_by
        )
    if not revoked:
        raise click.ClickException("Vulnerability approver credential not found")
    click.echo(json.dumps({"credential_id": credential_id, "revoked": True}))


@main.command("vuln-collect")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=db.DEFAULT_DB,
    show_default=True,
    help="SQLite database path",
)
@click.option("--once", is_flag=True, help="Run one scheduling and queue-consumption tick")
@click.option(
    "--interval",
    "interval_seconds",
    type=click.IntRange(min=5, max=86400),
    default=60,
    show_default=True,
    help="Seconds between scheduler ticks",
)
@click.option("--log-level", default="INFO", show_default=True, help="Log level")
def vuln_collect(db_path: Path, once: bool, interval_seconds: int, log_level: str):
    """Run the durable passive-collection scheduler and task consumer."""
    configure_logging(log_level)
    db.configure(db_path)
    from cairn.server.vulnerability_collectors import run_collector_loop

    try:
        run_collector_loop(interval_seconds=interval_seconds, once=once)
    except KeyboardInterrupt:
        return


@main.command("vuln-queue-maintain")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=db.DEFAULT_DB,
    show_default=True,
    help="SQLite database path",
)
@click.option("--apply", is_flag=True, help="Apply changes; otherwise report a dry run")
@click.option(
    "--compact-scheduled",
    is_flag=True,
    help="Archive historic queued scheduled/policy batches above the threshold",
)
@click.option("--compact-threshold", type=click.IntRange(min=1), default=100, show_default=True)
@click.option("--terminal-retention-days", type=click.IntRange(min=0), default=7, show_default=True)
@click.option("--pending-expiry-days", type=click.IntRange(min=1), default=30, show_default=True)
def vuln_queue_maintain(
    db_path: Path,
    apply: bool,
    compact_scheduled: bool,
    compact_threshold: int,
    terminal_retention_days: int,
    pending_expiry_days: int,
):
    """Expire stale approvals and archive retained collection queue records."""
    db.configure(db_path)
    from cairn.server.vulnerability_collectors import maintain_collection_queue

    with db.get_conn() as conn:
        result = maintain_collection_queue(
            conn,
            apply=apply,
            terminal_retention_days=terminal_retention_days,
            pending_expiry_days=pending_expiry_days,
            compact_scheduled=compact_scheduled,
            compact_threshold=compact_threshold,
        )
    click.echo(json.dumps(result, ensure_ascii=False, sort_keys=True))
