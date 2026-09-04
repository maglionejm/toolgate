"""Toolgate CLI assembly: root app, global options, top-level commands.
Command groups live in registry.py (identities/tools), governance.py
(grants/approvals/operators), channels.py (notifications), and forensics.py
(audit/token/dev)."""

from typing import Annotated

import httpx
import typer
from rich.panel import Panel

from toolgate import __version__

from . import channels, forensics, governance, registry  # noqa: F401 — attaches commands
from .client import err_console
from .config import save_profile
from .shared import (
    _table,
    agents_app,
    approvals_app,
    audit_app,
    channels_app,
    client,
    console,
    dev_app,
    emit,
    grants_app,
    keys_app,
    operators_app,
    policies_app,
    slack_app,
    state,
    tenants_app,
    token_app,
    upstreams_app,
    users_app,
    vault_app,
)

app = typer.Typer(no_args_is_help=True, help="Toolgate — capability control plane for AI agents.")

for name, sub in [
    ("keys", keys_app),
    ("tenants", tenants_app),
    ("users", users_app),
    ("agents", agents_app),
    ("upstreams", upstreams_app),
    ("policies", policies_app),
    ("grants", grants_app),
    ("approvals", approvals_app),
    ("audit", audit_app),
    ("token", token_app),
    ("dev", dev_app),
    ("operators", operators_app),
    ("channels", channels_app),
    ("slack", slack_app),
    ("vault", vault_app),
]:
    app.add_typer(sub, name=name)


@app.callback()
def _root(
    profile: Annotated[
        str | None, typer.Option("--profile", "-p", help="Config profile name.")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable JSON output.")] = False,
) -> None:
    state["profile"] = profile
    state["json"] = json_out


# ---------------------------------------------------------------------------
# top-level
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the Toolgate version."""
    console.print(f"toolgate {__version__}")


@app.command()
def init(
    url: Annotated[str, typer.Option(prompt="Toolgate URL")] = "http://localhost:8484",
    admin_key: Annotated[str, typer.Option(prompt="Admin key", hide_input=True)] = "",
    name: Annotated[str, typer.Option(help="Profile name.")] = "default",
) -> None:
    """Configure a profile and verify connectivity."""
    try:
        health = httpx.get(f"{url.rstrip('/')}/healthz", timeout=10.0).json()
    except httpx.HTTPError as err:
        err_console.print(f"[bold red]unreachable[/] {err}")
        raise typer.Exit(1) from err
    path = save_profile(name, url, admin_key)
    emit(
        {"profile": name, "url": url, "issuer": health.get("issuer")},
        Panel(
            f"profile [bold]{name}[/] -> {url}\nissuer {health.get('issuer')}\nsaved to {path}",
            title="connected",
            border_style="green",
        ),
    )


@app.command()
def report(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
) -> None:
    """Usage rollup derived from the signed audit chain."""
    data = client().get("/v1/control/reports", tenantId=tenant)
    tot = data["totals"]
    if state["json"]:
        emit(data)
        return
    console.print(
        Panel(
            f"calls [bold]{tot['calls']}[/] · executed {tot['executed']} · "
            f"denied {tot['denied']} · parked {tot['pendingApproval']} · "
            f"errors {tot['errors']}\ncost units spent [bold]{tot['costUnits']}[/] · "
            f"approvals executed {data['approvals']['executedAfterApproval']}"
            + (
                f" (avg {data['approvals']['avgApprovalToExecuteSeconds']}s to execute)"
                if data["approvals"]["avgApprovalToExecuteSeconds"] is not None
                else ""
            ),
            title=f"usage — {tenant}",
            border_style="green",
        )
    )
    console.print(
        _table(
            "by tool",
            ["tool", "calls", "executed", "denied", "cost"],
            [
                [r["tool"], str(r["calls"]), str(r["executed"]), str(r["denied"]),
                 str(r["costUnits"])]
                for r in data["byTool"]
            ],
        )
    )
    console.print(
        _table(
            "by agent",
            ["agent", "calls", "executed", "denied", "cost"],
            [
                [r["agentId"], str(r["calls"]), str(r["executed"]), str(r["denied"]),
                 str(r["costUnits"])]
                for r in data["byAgent"]
            ],
        )
    )


@app.command()
def up(
    image: Annotated[str, typer.Option("--image")] = "ghcr.io/maglionejm/toolgate:latest",
    port: Annotated[int, typer.Option("--port")] = 8484,
    env_file: Annotated[str, typer.Option("--env-file")] = ".toolgate.env",
) -> None:
    """Run Toolgate in Docker with generated fail-closed secrets.

    Creates an env file (0600) with TOOLGATE_MASTER_KEY / TOOLGATE_ADMIN_KEY on
    first use and starts the container with a persistent volume."""
    import secrets as _secrets
    import shutil
    import subprocess
    from pathlib import Path as _Path

    from .shared import _write_0600

    if shutil.which("docker") is None:
        err_console.print(
            "[bold red]docker not found[/] — install Docker, or run the process directly:\n"
            "  TOOLGATE_MASTER_KEY=... TOOLGATE_ADMIN_KEY=... toolgate server"
        )
        raise typer.Exit(1)

    env_path = _Path(env_file)
    if not env_path.exists():
        _write_0600(
            env_path,
            f"TOOLGATE_MASTER_KEY={_secrets.token_urlsafe(32)}\n"
            f"TOOLGATE_ADMIN_KEY=tgk_{_secrets.token_urlsafe(24)}\n"
            f"TOOLGATE_HOST=0.0.0.0\n"
            f"TOOLGATE_PUBLIC_URL=http://localhost:{port}\n",
        )
        console.print(f"[green]generated[/] {env_path} (0600) — keep it out of version control")

    cmd = [
        "docker", "run", "--rm", "-d",
        "--name", "toolgate",
        "-p", f"{port}:8484",
        "--env-file", str(env_path),
        "-v", "toolgate-data:/data",
        image,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        err_console.print(f"[bold red]docker run failed[/]\n{result.stderr.strip()}")
        raise typer.Exit(1)
    console.print(
        f"[green]toolgate running[/] on http://localhost:{port}\n"
        f"console: http://localhost:{port}/console · health: /healthz\n"
        f"admin key is in {env_path} — connect with `toolgate init`\n"
        f"stop with: docker stop toolgate"
    )


@app.command()
def server() -> None:
    """Run the Toolgate server (control plane + gate)."""
    from toolgate.server.main import main as server_main

    server_main()


@app.command()
def migrate(
    from_path: Annotated[
        str, typer.Option("--from", help="Source SQLite database file.")
    ],
    to_dsn: Annotated[
        str, typer.Option("--to", help="Target postgres:// DSN.")
    ],
) -> None:
    """Copy a SQLite store into Postgres verbatim and re-verify the audit chain."""
    from toolgate.server.store_pg import is_postgres_dsn, migrate_sqlite_to_postgres

    if not is_postgres_dsn(to_dsn):
        err_console.print("[bold red]--to must be a postgres:// DSN[/]")
        raise typer.Exit(1)
    result = migrate_sqlite_to_postgres(from_path, to_dsn)
    ok = result["valid"]
    emit(
        result,
        f"[{'green' if ok else 'red'}]migrated[/] {result['records']} audit records "
        f"(+{sum(result['tables'].values()) - result['records']} rows across "
        f"{len(result['tables'])} tables) · chain on target: "
        f"{'VALID' if ok else 'BROKEN'} · length {result['length']}",
    )
    raise typer.Exit(0 if ok else 2)


@app.command()
def demo(
    live: bool = typer.Option(
        False,
        "--live",
        help="Drive the demo with a real Claude model, including the "
        "prompt-injection containment act (needs ANTHROPIC_API_KEY).",
    ),
) -> None:
    """Run the end-to-end demo (scripted, or --live with a real model)."""
    if live:
        from toolgate.demo_live import main as live_main

        live_main()
    else:
        from toolgate.demo import main as demo_main

        demo_main()




def main() -> None:
    app()


if __name__ == "__main__":
    main()
