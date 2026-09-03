import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from toolgate import __version__
from toolgate.core import (
    AuditRecord,
    Checkpoint,
    generate_ed25519_key_pair,
    jwk_thumbprint,
    validate_public_ed25519_jwk,
    verify_audit_chain,
    verify_capability_token,
    verify_checkpoint,
)

from .client import AdminClient, err_console
from .config import resolve, save_profile

app = typer.Typer(no_args_is_help=True, help="Toolgate — capability control plane for AI agents.")
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
def server() -> None:
    """Run the Toolgate server (control plane + gate)."""
    from toolgate.server.main import main as server_main

    server_main()


@app.command()
def demo() -> None:
    """Run the six-act end-to-end demo."""
    from toolgate.demo import main as demo_main

    demo_main()


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


@keys_app.command("generate")
def keys_generate(
    out: Annotated[Path, typer.Option(help="Private JWK destination (0600).")] = Path(
        "agent-key.json"
    ),
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing key file.")
    ] = False,
) -> None:
    """Generate an agent Ed25519 keypair. The private key never leaves this machine."""
    if out.exists() and not force:
        err_console.print(
            f"[bold red]exists[/] {escape(str(out))} already exists — refusing to overwrite; "
            "pass [bold]--force[/] to replace it"
        )
        raise typer.Exit(1)
    pair = generate_ed25519_key_pair()
    _write_0600(out, json.dumps(pair.private_jwk, indent=2) + "\n")
    emit(
        {"kid": pair.kid, "publicJwk": pair.public_jwk, "privateKeyFile": str(out)},
        Panel(
            f"kid [bold]{pair.kid}[/]\nprivate key -> {out} (0600) — keep it with the agent\n"
            f"public JWK (register with [bold]toolgate agents register --key {out}[/]):\n"
            f"{json.dumps(pair.public_jwk)}",
            title="keypair generated",
            border_style="green",
        ),
    )


# ---------------------------------------------------------------------------
# tenants / users / agents
# ---------------------------------------------------------------------------


@tenants_app.command("create")
def tenants_create(name: str) -> None:
    data = client().post("/v1/control/tenants", {"name": name})
    emit(data, f"[green]created[/] tenant [bold]{data['id']}[/] ({name})")


@tenants_app.command("list")
def tenants_list() -> None:
    data = client().get("/v1/control/tenants")
    emit(
        data,
        _table(
            "tenants",
            ["id", "name", "created"],
            [[t["id"], t["name"], t["createdAt"][:19]] for t in data],
        ),
    )


@users_app.command("create")
def users_create(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    name: Annotated[str, typer.Option("--name")],
    email: Annotated[str | None, typer.Option("--email")] = None,
) -> None:
    body: dict[str, Any] = {"tenantId": tenant, "displayName": name}
    if email:
        body["email"] = email
    data = client().post("/v1/control/users", body)
    emit(data, f"[green]created[/] user [bold]{data['id']}[/] ({name})")


@users_app.command("list")
def users_list(tenant: Annotated[str, typer.Option("--tenant", "-t")]) -> None:
    data = client().get("/v1/control/users", tenantId=tenant)
    emit(
        data,
        _table(
            "users",
            ["id", "name", "email"],
            [[u["id"], u["displayName"], u.get("email", "—")] for u in data],
        ),
    )


@agents_app.command("register")
def agents_register(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    name: Annotated[str, typer.Option("--name")],
    key: Annotated[
        Path,
        typer.Option("--key", help="Agent Ed25519 JWK file; only the public half is sent."),
    ],
) -> None:
    jwk = json.loads(key.read_text())
    # Accept the generated private key file (the documented flow) or a bare
    # public key, but only ever send the public half. Reject non-Ed25519 keys
    # (e.g. symmetric `oct` or EC) up front so a bad key never reaches the server.
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        err_console.print(
            "[bold red]invalid key[/] agent key must be an Ed25519 (OKP) JWK with a public 'x'"
        )
        raise typer.Exit(1)
    public = {k: jwk[k] for k in ("kty", "crv", "x")}
    public["kid"] = jwk.get("kid") or jwk_thumbprint(public)
    public["alg"] = "EdDSA"
    # Defensive: the extracted public JWK must satisfy the strict validator
    # (never carries private material) before we send it.
    validate_public_ed25519_jwk(public)
    data = client().post(
        "/v1/control/agents", {"tenantId": tenant, "name": name, "publicJwk": public}
    )
    emit(
        data,
        f"[green]registered[/] agent [bold]{data['id']}[/] ({name}, kid {public['kid'][:12]}…)",
    )


@agents_app.command("list")
def agents_list(tenant: Annotated[str, typer.Option("--tenant", "-t")]) -> None:
    data = client().get("/v1/control/agents", tenantId=tenant)
    emit(
        data,
        _table(
            "agents", ["id", "name", "status"], [[a["id"], a["name"], a["status"]] for a in data]
        ),
    )


# ---------------------------------------------------------------------------
# upstreams / policies
# ---------------------------------------------------------------------------


def _parse_tool(spec: str) -> dict[str, Any]:
    """name[:cost][:se] — e.g. 'read_contact', 'send_email:2:se'."""
    parts = spec.split(":")
    tool: dict[str, Any] = {"name": parts[0]}
    if len(parts) > 1 and parts[1]:
        tool["costUnits"] = int(parts[1])
    if len(parts) > 2 and parts[2] == "se":
        tool["sideEffecting"] = True
    return tool


@upstreams_app.command("add")
def upstreams_add(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    name: Annotated[str, typer.Option("--name")],
    base_url: Annotated[str, typer.Option("--base-url")],
    tool: Annotated[list[str], typer.Option("--tool", help="name[:cost][:se], repeatable.")],
    mode: Annotated[str, typer.Option("--mode")] = "bearer",
    secret: Annotated[
        str, typer.Option("--secret", prompt="Upstream credential", hide_input=True)
    ] = "",
    header_name: Annotated[str | None, typer.Option("--header-name")] = None,
    param_name: Annotated[str | None, typer.Option("--param-name")] = None,
) -> None:
    """Register a tool backend; its credential is sealed into the vault and never shown again."""
    credential: dict[str, Any] = {"mode": mode, "secret": secret}
    if header_name:
        credential["headerName"] = header_name
    if param_name:
        credential["paramName"] = param_name
    data = client().post(
        "/v1/control/upstreams",
        {
            "tenantId": tenant,
            "name": name,
            "baseUrl": base_url,
            "credential": credential,
            "tools": [_parse_tool(s) for s in tool],
        },
    )
    emit(
        data,
        f"[green]added[/] upstream [bold]{data['id']}[/] "
        f"({name}, {len(tool)} tools, credential sealed)",
    )


@upstreams_app.command("list")
def upstreams_list(tenant: Annotated[str, typer.Option("--tenant", "-t")]) -> None:
    data = client().get("/v1/control/upstreams", tenantId=tenant)
    rows = [
        [u["id"], u["name"], u["baseUrl"], ", ".join(t["name"] for t in u["tools"])] for u in data
    ]
    emit(data, _table("upstreams", ["id", "name", "base url", "tools"], rows))


@policies_app.command("create")
def policies_create(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    name: Annotated[str, typer.Option("--name")],
    rules_file: Annotated[Path, typer.Option("--rules-file", help="JSON array of policy rules.")],
) -> None:
    rules = json.loads(rules_file.read_text())
    data = client().post(
        "/v1/control/policies", {"tenantId": tenant, "name": name, "rules": rules}
    )
    emit(
        data,
        f"[green]created[/] policy [bold]{data['id']}[/] "
        f"({name}, {len(rules)} rules, default deny)",
    )


@policies_app.command("list")
def policies_list(tenant: Annotated[str, typer.Option("--tenant", "-t")]) -> None:
    data = client().get("/v1/control/policies", tenantId=tenant)
    emit(
        data,
        _table(
            "policies",
            ["id", "name", "rules"],
            [[p["id"], p["name"], str(len(p["rules"]))] for p in data],
        ),
    )


# ---------------------------------------------------------------------------
# grants
# ---------------------------------------------------------------------------


def _parse_authz(spec: str) -> dict[str, Any]:
    """'crm:*' or 'email:send_email,draft_email' -> authorization detail."""
    upstream, _, tools = spec.partition(":")
    return {"upstream": upstream, "tools": [t.strip() for t in (tools or "*").split(",")]}


@grants_app.command("create")
def grants_create(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    user: Annotated[str, typer.Option("--user")],
    agent: Annotated[str, typer.Option("--agent")],
    policy: Annotated[str, typer.Option("--policy")],
    budget: Annotated[int, typer.Option("--budget")],
    authz: Annotated[
        list[str], typer.Option("--authz", help="upstream:tool1,tool2 or upstream:* — repeatable.")
    ],
    ttl_hours: Annotated[float, typer.Option("--ttl-hours")] = 24,
    scope: Annotated[list[str] | None, typer.Option("--scope")] = None,
) -> None:
    data = client().post(
        "/v1/control/grants",
        {
            "tenantId": tenant,
            "userId": user,
            "agentId": agent,
            "policyId": policy,
            "budgetMaxUnits": budget,
            "ttlHours": ttl_hours,
            "scopes": scope or [],
            "authorization": [_parse_authz(s) for s in authz],
        },
    )
    emit(data, f"[green]delegated[/] grant [bold]{data['id']}[/] (budget {budget}, {ttl_hours}h)")


def _budget_bar(spent: int, max_units: int, width: int = 16) -> str:
    used = round(width * spent / max_units) if max_units else 0
    return f"[{'#' * used}{'-' * (width - used)}] {spent}/{max_units}"


@grants_app.command("list")
def grants_list(tenant: Annotated[str, typer.Option("--tenant", "-t")]) -> None:
    data = client().get("/v1/control/grants", tenantId=tenant)
    rows = [
        [
            g["id"],
            g["agentId"],
            _budget_bar(g["budget"]["spentUnits"], g["budget"]["maxUnits"]),
            g["status"],
            g["expiresAt"][:19],
        ]
        for g in data
    ]
    emit(data, _table("grants", ["id", "agent", "budget", "status", "expires"], rows))


@grants_app.command("show")
def grants_show(grant_id: str) -> None:
    g = client().get(f"/v1/control/grants/{grant_id}")
    authz = "\n".join(f"  {d['upstream']}: {', '.join(d['tools'])}" for d in g["authorization"])
    emit(
        g,
        Panel(
            f"user [bold]{g['userId']}[/] -> agent [bold]{g['agentId']}[/]\n"
            f"status [bold]{g['status']}[/] · expires {g['expiresAt'][:19]}\n"
            f"budget {_budget_bar(g['budget']['spentUnits'], g['budget']['maxUnits'])}\n"
            f"policy {g['policyId']}\nauthorization:\n{authz}",
            title=f"grant {g['id']}",
            border_style="green" if g["status"] == "active" else "red",
        ),
    )


@grants_app.command("revoke")
def grants_revoke(
    grant_id: str,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
) -> None:
    """Kill switch: live tokens minted from this grant die on their next call."""
    if not yes and not typer.confirm(f"Revoke {grant_id}? Live tokens die immediately."):
        raise typer.Exit(0)
    data = client().post(f"/v1/control/grants/{grant_id}/revoke")
    emit(data, f"[red]revoked[/] {data['id']}")


# ---------------------------------------------------------------------------
# approvals
# ---------------------------------------------------------------------------


@approvals_app.command("list")
def approvals_list(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    status: Annotated[str | None, typer.Option("--status")] = "pending",
) -> None:
    data = client().get("/v1/control/approvals", tenantId=tenant, status=status)
    rows = [
        [
            a["id"],
            f"{a['upstream']}.{a['tool']}",
            json.dumps(a["args"])[:48],
            a["status"],
            a["requestedAt"][11:19],
        ]
        for a in data
    ]
    emit(data, _table(f"approvals ({status})", ["id", "call", "args", "status", "at"], rows))


def _decide(approval_id: str, decision: str, by: str | None) -> None:
    body: dict[str, Any] = {"decision": decision}
    if by:
        body["decidedBy"] = by
    data = client().post(f"/v1/control/approvals/{approval_id}/decide", body)
    color = "green" if decision == "approve" else "red"
    emit(data, f"[{color}]{data['status']}[/] {approval_id} by {by}")


@approvals_app.command("approve")
def approvals_approve(
    approval_id: str,
    by: Annotated[str | None, typer.Option("--by", help="Decider (defaults to operator).")] = None,
) -> None:
    _decide(approval_id, "approve", by)


@approvals_app.command("deny")
def approvals_deny(
    approval_id: str,
    by: Annotated[str | None, typer.Option("--by", help="Decider (defaults to operator).")] = None,
) -> None:
    _decide(approval_id, "deny", by)


def _watch_decision(choice: str) -> str | None:
    """Map a watch-prompt answer to a decision. EXACT matching only: 'abort',
    'argh', etc. must NOT be read as 'approve'. Anything unrecognised = skip."""
    c = choice.strip().lower()
    if c in {"approve", "a", "y"}:
        return "approve"
    if c in {"deny", "d", "n"}:
        return "deny"
    return None


@approvals_app.command("watch")
def approvals_watch(
    tenant: Annotated[str, typer.Option("--tenant", "-t")],
    by: Annotated[str, typer.Option("--by", help="Deciding user id.")],
    interval: Annotated[float, typer.Option("--interval")] = 2.0,
) -> None:
    """Interactive inbox: prompts on each new pending approval. Ctrl-C to stop."""
    c = client()
    seen: set[str] = set()
    console.print(f"[dim]watching approvals for {tenant} — Ctrl-C to stop[/]")
    try:
        while True:
            for a in c.get("/v1/control/approvals", tenantId=tenant, status="pending"):
                if a["id"] in seen:
                    continue
                seen.add(a["id"])
                console.print(
                    Panel(
                        f"[bold]{a['upstream']}.{a['tool']}[/]\n"
                        f"agent {a['agentId']} · for {a['userId']}\n"
                        f"args:\n{json.dumps(a['args'], indent=2)}",
                        title=f"pending {a['id']}",
                        border_style="yellow",
                    )
                )
                choice = typer.prompt("approve / deny / skip", default="skip")
                decision = _watch_decision(choice)
                if decision == "approve":
                    _decide(a["id"], "approve", by)
                elif decision == "deny":
                    _decide(a["id"], "deny", by)
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("[dim]stopped[/]")


@operators_app.command("create")
def operators_create(
    name: Annotated[str, typer.Option("--name")],
    role: Annotated[str, typer.Option("--role", help="owner | approver | auditor")],
) -> None:
    """Create an operator; the opk_ key is printed exactly once."""
    data = client().post("/v1/control/operators", {"name": name, "role": role})
    emit(
        data,
        Panel(
            f"operator [bold]{data['operator']['id']}[/] ({name}, {role})\n"
            f"key (shown once, store it now): [bold]{data['key']}[/]",
            title="operator created",
            border_style="green",
        ),
    )


@operators_app.command("list")
def operators_list() -> None:
    data = client().get("/v1/control/operators")
    emit(
        data,
        _table(
            "operators",
            ["id", "name", "role", "status"],
            [[o["id"], o["name"], o["role"], o["status"]] for o in data],
        ),
    )


@operators_app.command("disable")
def operators_disable(operator_id: str) -> None:
    data = client().post(f"/v1/control/operators/{operator_id}/disable")
    emit(data, f"[red]disabled[/] {data['id']}")


@policies_app.command("simulate")
def policies_simulate(
    policy_id: str,
    upstream: Annotated[str, typer.Option("--upstream")],
    tool: Annotated[str, typer.Option("--tool")],
    args: Annotated[str, typer.Option("--args")] = "{}",
    cost: Annotated[int, typer.Option("--cost")] = 1,
    tainted: Annotated[bool, typer.Option("--tainted", help="Simulate a tainted task.")] = False,
) -> None:
    """Dry-run a call against a policy: would the gate allow it?"""
    data = client().post(
        f"/v1/control/policies/{policy_id}/simulate",
        {
            "upstream": upstream,
            "tool": tool,
            "args": json.loads(args),
            "costUnits": cost,
            "tainted": tainted,
        },
    )
    color = {"allow": "green", "deny": "red", "require_approval": "yellow"}[data["effect"]]
    emit(
        data,
        f"[{color}]{data['effect']}[/] ({data['source']}"
        + (f", rule {data['ruleId']}" if data.get("ruleId") else "")
        + f") — {data['reason']}",
    )


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


@audit_app.command("list")
def audit_list(
    tenant: Annotated[str | None, typer.Option("--tenant", "-t")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 50,
) -> None:
    data = client().get("/v1/control/audit", tenantId=tenant)
    rows = [
        [
            str(r["seq"]),
            r["ts"][11:19],
            f"{r['action']['upstream']}.{r['action']['tool']}",
            f"{r['decision']['effect']} ({r['decision']['source']})",
            r["result"]["status"],
            str(r["result"].get("costUnits", "—")),
        ]
        for r in data[-limit:]
    ]
    emit(data, _table("audit", ["seq", "time", "call", "decision", "result", "cost"], rows))


@audit_app.command("verify")
def audit_verify(
    file: Annotated[
        Path | None, typer.Option("--file", help="Offline: verify an exported chain file.")
    ] = None,
    jwk_file: Annotated[
        Path | None,
        typer.Option("--jwk", help="Gate public JWK (offline; default fetches /v1/keys)."),
    ] = None,
) -> None:
    """Verify the audit chain — server-side, or fully offline from an export."""
    if file is None:
        data = client().get("/v1/control/audit/verify")
        ok = data["valid"]
        emit(
            data,
            f"[{'green' if ok else 'red'}]valid: {ok}[/] · length {data['length']}"
            + (f" · broken at seq {data['broken_at_seq']}: {data['reason']}" if not ok else ""),
        )
        raise typer.Exit(0 if ok else 2)

    exported = json.loads(file.read_text())
    # Bundle exports carry {records, checkpoints}; bare record arrays still work.
    raw_records = exported["records"] if isinstance(exported, dict) else exported
    raw_checkpoints = exported.get("checkpoints", []) if isinstance(exported, dict) else []
    records = [AuditRecord.model_validate(r) for r in raw_records]

    if jwk_file:
        loaded = json.loads(jwk_file.read_text())
        keys = (
            {k.get("kid", ""): k for k in loaded["keys"]} if "keys" in loaded else loaded
        )
    else:
        remote = client().public("/v1/keys")
        keys = {k.get("kid", ""): k for k in remote["gate_jwks"]["keys"]}

    result = verify_audit_chain(records, keys)
    checkpoints = [Checkpoint.model_validate(c) for c in raw_checkpoints]
    cp_valid = sum(1 for c in checkpoints if verify_checkpoint(c, records, keys))
    payload = {
        "valid": result.valid,
        "length": result.length,
        "checkpoints_valid": cp_valid,
        "checkpoints_total": len(checkpoints),
        **(
            {"broken_at_seq": result.broken_at_seq, "reason": result.reason}
            if not result.valid
            else {}
        ),
    }
    ok = result.valid and cp_valid == len(checkpoints)
    emit(
        payload,
        f"[{'green' if ok else 'red'}]valid: {result.valid}[/] · length {result.length}"
        + f" · checkpoints {cp_valid}/{len(checkpoints)}"
        + (f" · broken at seq {result.broken_at_seq}: {result.reason}" if not result.valid else ""),
    )
    raise typer.Exit(0 if ok else 2)


@audit_app.command("export")
def audit_export(
    out: Annotated[Path, typer.Option("--out")] = Path("audit-export.json"),
) -> None:
    """Export the full chain + signed checkpoints (all tenants — partial
    chains cannot be verified)."""
    data = client().get("/v1/control/audit/bundle")
    text = json.dumps(data, indent=2)
    out.write_text(text + "\n")
    digest = hashlib.sha256(text.encode()).hexdigest()
    emit(
        {
            "file": str(out),
            "records": len(data["records"]),
            "checkpoints": len(data["checkpoints"]),
            "sha256": digest,
        },
        f"[green]exported[/] {len(data['records'])} records + "
        f"{len(data['checkpoints'])} checkpoints -> {out}\nsha256 {digest}",
    )


# ---------------------------------------------------------------------------
# token
# ---------------------------------------------------------------------------


def _b64json(part: str) -> dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


@token_app.command("decode")
def token_decode(
    token: str,
    verify: Annotated[
        bool, typer.Option("--verify", help="Verify signature against /v1/keys.")
    ] = False,
) -> None:
    header, payload = token.split(".")[0:2]
    decoded = {"header": _b64json(header), "claims": _b64json(payload)}
    if not verify:
        decoded["verified"] = False
        emit(
            decoded,
            Panel(
                json.dumps(decoded, indent=2), title="decoded (NOT verified)", border_style="yellow"
            ),
        )
        return
    keys = client().public("/v1/keys")
    claims = verify_capability_token(
        keys["control"], token, issuer=keys["issuer"], audience=keys["gate_audience"]
    )
    decoded["verified"] = True
    decoded["claims"] = claims.model_dump(mode="json")
    emit(
        decoded,
        Panel(json.dumps(decoded["claims"], indent=2), title="verified", border_style="green"),
    )


# ---------------------------------------------------------------------------
# dev harness
# ---------------------------------------------------------------------------


def _agent_client(grant: str, key: Path) -> Any:
    from toolgate.sdk import ToolgateClient

    profile = resolve(state["profile"])
    grant_info = client().get(f"/v1/control/grants/{grant}")
    return ToolgateClient(
        base_url=profile.url,
        agent_id=grant_info["agentId"],
        agent_private_jwk=json.loads(key.read_text()),
        grant_id=grant,
    )


@dev_app.command("execute")
def dev_execute(
    approval_id: str,
    grant: Annotated[str, typer.Option("--grant")],
    key: Annotated[Path, typer.Option("--key", help="Agent private JWK file.")],
) -> None:
    """Act as the agent: execute an already-approved parked call."""
    from toolgate.sdk import ToolgateCallError

    try:
        done = _agent_client(grant, key).execute_approval(approval_id)
        emit(
            {"status": "executed", "result": done.result},
            f"[green]executed[/] approved call -> {json.dumps(done.result)}",
        )
    except ToolgateCallError as err:
        err_console.print(f"[bold red]{escape(err.code)}[/] {escape(err.message)}")
        raise typer.Exit(1) from err


@dev_app.command("call")
def dev_call(
    upstream: str,
    tool: str,
    grant: Annotated[str, typer.Option("--grant")],
    key: Annotated[Path, typer.Option("--key", help="Agent private JWK file.")],
    args: Annotated[str, typer.Option("--args")] = "{}",
    wait: Annotated[
        bool, typer.Option("--wait", help="Poll until a parked call is decided.")
    ] = False,
) -> None:
    """Act as the agent: exchange the key + grant for a token and call through the gate."""
    from toolgate.sdk import PendingApproval, ToolgateCallError

    agent_client = _agent_client(grant, key)
    try:
        result = agent_client.call(upstream, tool, json.loads(args))
        if isinstance(result, PendingApproval):
            emit(
                {"status": "pending_approval", "approval_id": result.approval_id},
                f"[yellow]parked[/] approval [bold]{result.approval_id}[/] — decide with "
                f"`toolgate approvals approve {result.approval_id} --by usr_...`",
            )
            if wait:
                with console.status("waiting for the human…"):
                    done = agent_client.wait_for_approval(result.approval_id)
                emit(
                    {"status": "executed", "result": done.result},
                    f"[green]executed[/] after approval -> {json.dumps(done.result)}",
                )
        else:
            emit(
                {"status": "executed", "result": result.result},
                f"[green]executed[/] -> {json.dumps(result.result)}",
            )
    except ToolgateCallError as err:
        err_console.print(f"[bold red]{escape(err.code)}[/] {escape(err.message)}")
        raise typer.Exit(1) from err


def main() -> None:
    app()


if __name__ == "__main__":
    main()
