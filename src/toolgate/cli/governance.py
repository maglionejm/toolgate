import json
import time
from typing import Annotated, Any

import typer
from rich.panel import Panel

from .shared import (
    _table,
    approvals_app,
    client,
    console,
    emit,
    grants_app,
    operators_app,
    policies_app,
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


