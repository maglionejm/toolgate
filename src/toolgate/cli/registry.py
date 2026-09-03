import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel

from toolgate.core import (
    generate_ed25519_key_pair,
    jwk_thumbprint,
    validate_public_ed25519_jwk,
)

from .client import err_console
from .shared import (
    _table,
    _write_0600,
    agents_app,
    client,
    emit,
    escape,
    keys_app,
    policies_app,
    tenants_app,
    upstreams_app,
    users_app,
)

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


