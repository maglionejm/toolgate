"""Shared CLI state, helpers, and command groups."""

import json
import os
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .client import AdminClient, err_console
from .config import resolve

__all__ = [
    "_table",
    "_write_0600",
    "agents_app",
    "approvals_app",
    "audit_app",
    "channels_app",
    "client",
    "console",
    "dev_app",
    "emit",
    "escape",
    "grants_app",
    "keys_app",
    "oauth_app",
    "operators_app",
    "policies_app",
    "slack_app",
    "state",
    "tenants_app",
    "token_app",
    "upstreams_app",
    "users_app",
    "vault_app",
]

console = Console()
state: dict[str, Any] = {"profile": None, "json": False}

keys_app = typer.Typer(no_args_is_help=True, help="Agent keypairs.")
tenants_app = typer.Typer(no_args_is_help=True, help="Tenants.")
users_app = typer.Typer(no_args_is_help=True, help="Human principals.")
agents_app = typer.Typer(no_args_is_help=True, help="Agent identities (public keys only).")
upstreams_app = typer.Typer(no_args_is_help=True, help="Tool backends + sealed credentials.")
policies_app = typer.Typer(no_args_is_help=True, help="Ordered policy rules.")
grants_app = typer.Typer(no_args_is_help=True, help="Delegations: user -> agent, bounded.")
approvals_app = typer.Typer(no_args_is_help=True, help="Human-in-the-loop approvals inbox.")
audit_app = typer.Typer(no_args_is_help=True, help="Signed audit chain.")
token_app = typer.Typer(no_args_is_help=True, help="Capability token utilities.")
dev_app = typer.Typer(no_args_is_help=True, help="Developer harness (acts as an agent).")
operators_app = typer.Typer(no_args_is_help=True, help="Control-plane operators and roles.")
channels_app = typer.Typer(
    no_args_is_help=True, help="Approval notification channels (webhook, Slack, email)."
)
slack_app = typer.Typer(no_args_is_help=True, help="Slack user <-> operator bindings.")
vault_app = typer.Typer(no_args_is_help=True, help="Secret vault lifecycle (KEK, migration).")
oauth_app = typer.Typer(
    no_args_is_help=True, help="Per-user OAuth connections (provider apps, connect, revoke)."
)


def client() -> AdminClient:
    try:
        return AdminClient(resolve(state["profile"]))
    except LookupError as err:
        err_console.print(f"[bold red]config[/] {err}")
        raise typer.Exit(1) from err


def emit(data: Any, render: Any = None) -> None:
    """--json prints the raw API payload; otherwise the rich rendering."""
    if state["json"]:
        console.print_json(json.dumps(data))
    elif render is not None:
        console.print(render)


def _table(title: str, columns: list[str], rows: list[list[str]]) -> Table:
    t = Table(title=title, title_justify="left", header_style="bold")
    for c in columns:
        t.add_column(c)
    for r in rows:
        t.add_row(*r)
    return t


def _write_0600(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` created already at mode 0600 — no default-umask
    (0644) window and nothing left world-readable if the process crashes."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(text)
