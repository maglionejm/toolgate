import base64
import hashlib
import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel

from toolgate.core import (
    AuditRecord,
    Checkpoint,
    verify_audit_chain,
    verify_capability_token,
    verify_checkpoint,
)

from .client import err_console
from .config import resolve
from .shared import _table, audit_app, client, console, dev_app, emit, escape, state, token_app

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


