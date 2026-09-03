"""Six-act demo: an embedded agent that never holds a credential.

Boots Toolgate plus two credential-guarded mock APIs on localhost and runs the
full scenario: allowed call, policy denial, human approval, budget exhaustion,
mid-task revocation, audit verification. Run with: uv run toolgate-demo
"""

import threading
import time
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from toolgate.sdk import (
    PendingApproval,
    ToolgateCallError,
    ToolgateClient,
    generate_ed25519_key_pair,
)
from toolgate.server import create_app, create_app_context

GATE_PORT = 8491
UPSTREAM_PORT = 8492
GATE_URL = f"http://localhost:{GATE_PORT}"
UPSTREAM_URL = f"http://localhost:{UPSTREAM_PORT}"

# Obvious fakes: these are demo-only mock upstream credentials, never real keys.
CRM_SECRET = "demo-crm-mock-secret"  # noqa: S105 - not a real credential
EMAIL_SECRET = "demo-email-mock-secret"  # noqa: S105 - not a real credential


def line(tag: str, msg: str) -> None:
    print(f"  [{tag:<8}] {msg}")


def section(title: str) -> None:
    print(f"\n— {title} " + "—" * max(1, 72 - len(title)))


def make_upstreams() -> FastAPI:
    """Mock third-party APIs. They require real credentials — exactly the
    secrets the agent must never see. If Toolgate fails to inject them, these
    return 401 and the demo fails loudly."""
    app = FastAPI()

    @app.post("/crm/tools/{tool}")
    async def crm(tool: str, request: Request) -> Any:
        if request.headers.get("authorization") != f"Bearer {CRM_SECRET}":
            return JSONResponse(status_code=401, content={"error": "bad or missing CRM credential"})
        args = await request.json()
        if tool == "read_contact":
            return {
                "contact": {
                    "id": args.get("contactId", "c-001"),
                    "name": "Rivera, Ana",
                    "company": "Globex",
                }
            }
        if tool == "list_contacts":
            return {"contacts": 42}
        if tool == "delete_contact":
            return {"deleted": args.get("contactId")}
        return JSONResponse(status_code=404, content={"error": f"unknown tool {tool}"})

    @app.post("/email/tools/send_email")
    async def send_email(
        request: Request, x_api_key: str | None = Header(default=None)
    ) -> Any:
        if x_api_key != EMAIL_SECRET:
            return JSONResponse(
                status_code=401, content={"error": "bad or missing email credential"}
            )
        args = await request.json()
        return {"sent": True, "to": args.get("to"), "messageId": f"msg_{int(time.time() * 1000)}"}

    return app


def serve_in_thread(app: FastAPI, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    return server


def main() -> None:
    print("\nTOOLGATE DEMO — an embedded agent that never holds a credential\n")

    ctx = create_app_context(db_path=":memory:", public_url=GATE_URL)
    servers = [
        serve_in_thread(create_app(ctx), GATE_PORT),
        serve_in_thread(make_upstreams(), UPSTREAM_PORT),
    ]
    admin = {"x-toolgate-admin-key": ctx.config.admin_key}
    admin_http = httpx.Client(base_url=GATE_URL, headers=admin, timeout=10.0)

    def admin_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = admin_http.post(path, json=body)
        res.raise_for_status()
        return res.json()

    section("Setup: tenant, human, agent identity, tools, policy, delegation")
    tenant = admin_post("/v1/control/tenants", {"name": "Acme Corp"})
    user = admin_post(
        "/v1/control/users",
        {
            "tenantId": tenant["id"],
            "displayName": "Sam (account executive)",
            "email": "sam@acme.com",
        },
    )
    agent_keys = generate_ed25519_key_pair()
    agent = admin_post(
        "/v1/control/agents",
        {"tenantId": tenant["id"], "name": "inbox-assistant", "publicJwk": agent_keys.public_jwk},
    )
    line("SETUP", f"agent '{agent['name']}' registered — Toolgate stores only its PUBLIC key")

    admin_post(
        "/v1/control/upstreams",
        {
            "tenantId": tenant["id"],
            "name": "crm",
            "baseUrl": f"{UPSTREAM_URL}/crm",
            "credential": {"mode": "bearer", "secret": CRM_SECRET},
            "tools": [
                {"name": "read_contact", "costUnits": 1},
                {"name": "list_contacts", "costUnits": 1},
                {"name": "delete_contact", "sideEffecting": True, "costUnits": 1},
            ],
        },
    )
    admin_post(
        "/v1/control/upstreams",
        {
            "tenantId": tenant["id"],
            "name": "email",
            "baseUrl": f"{UPSTREAM_URL}/email",
            "credential": {"mode": "header", "headerName": "X-Api-Key", "secret": EMAIL_SECRET},
            "tools": [{"name": "send_email", "sideEffecting": True, "costUnits": 2}],
        },
    )
    line("SETUP", "upstream credentials sealed into the vault (AES-256-GCM)")

    policy = admin_post(
        "/v1/control/policies",
        {
            "tenantId": tenant["id"],
            "name": "sam-assistant-policy",
            "rules": [
                {
                    "id": "never-delete",
                    "effect": "deny",
                    "match": {"upstream": "crm", "tool": "delete_*"},
                },
                {
                    "id": "external-email-needs-human",
                    "effect": "require_approval",
                    "match": {
                        "upstream": "email",
                        "tool": "send_email",
                        "where": [{"path": "to", "op": "matches", "value": "@(?!acme\\.com$)"}],
                    },
                },
                {
                    "id": "internal-email-ok",
                    "effect": "allow",
                    "match": {"upstream": "email", "tool": "send_email"},
                },
                {"id": "crm-ok", "effect": "allow", "match": {"upstream": "crm", "tool": "*"}},
            ],
        },
    )
    grant = admin_post(
        "/v1/control/grants",
        {
            "tenantId": tenant["id"],
            "userId": user["id"],
            "agentId": agent["id"],
            "policyId": policy["id"],
            "scopes": ["crm", "email"],
            "authorization": [
                {"upstream": "crm", "tools": ["*"]},
                {"upstream": "email", "tools": ["send_email"]},
            ],
            "budgetMaxUnits": 8,
            "ttlHours": 8,
        },
    )
    line("SETUP", f"Sam delegated bounded authority (grant {grant['id']}, budget 8 units, 8h)")

    client = ToolgateClient(
        base_url=GATE_URL,
        agent_id=agent["id"],
        agent_private_jwk=agent_keys.private_jwk,
        grant_id=grant["id"],
    )

    section("1. Allowed call — credential injected server-side, invisible to the agent")
    read = client.call("crm", "read_contact", {"contactId": "c-001"})
    line("OK", f"read_contact executed -> {read.result}")
    line("NOTE", "the CRM demanded its live API key; the agent never saw it")

    section("2. Policy denial — the agent tries to delete a contact")
    try:
        client.call("crm", "delete_contact", {"contactId": "c-001"})
    except ToolgateCallError as err:
        line("DENIED", f"{err.code}: {err.message}")

    section("3. Human-in-the-loop — external email parks until Sam approves")
    parked = client.call(
        "email",
        "send_email",
        {
            "to": "cfo@globex.com",
            "subject": "Renewal proposal",
            "body": "Hi — attached the renewal terms we discussed.",
        },
    )
    assert isinstance(parked, PendingApproval)
    line("PARKED", f"approval {parked.approval_id} pending — agent is blocked, not trusted")

    def approve() -> None:
        admin_post(
            f"/v1/control/approvals/{parked.approval_id}/decide",
            {"decision": "approve", "decidedBy": user["id"]},
        )
        line("HUMAN", "Sam approved the exact parked arguments (args are hash-bound)")

    threading.Timer(1.2, approve).start()
    sent = client.wait_for_approval(parked.approval_id, poll_seconds=0.3)
    line("OK", f"send_email executed after approval -> {sent.result}")

    section("4. Budget — the delegation runs out of units")
    # Spent so far: 1 (read) + 2 (email) = 3 of 8. Burn past the cap.
    for i in range(6):
        try:
            client.call("crm", "list_contacts", {"page": i})
            line("OK", f"list_contacts page {i} (1 unit)")
        except ToolgateCallError as err:
            if err.code == "TG_BUDGET_EXCEEDED":
                line("BUDGET", f"blocked: {err.message} — delegation cannot overspend")
                break
            raise

    section("5. Revocation — Sam pulls the plug while the agent holds a live token")
    client.token()
    admin_post(f"/v1/control/grants/{grant['id']}/revoke", {})
    try:
        client.call("crm", "read_contact", {"contactId": "c-002"})
    except ToolgateCallError as err:
        line("REVOKED", f"{err.code}: live token died with the grant, no TTL wait")

    section("6. Audit — every decision above is in a signed hash chain")
    verification = admin_http.get("/v1/control/audit/verify").json()
    status = "VALID" if verification["valid"] else "BROKEN"
    line("AUDIT", f"chain of {verification['length']} records — verification: {status}")

    records = admin_http.get("/v1/control/audit", params={"tenantId": tenant["id"]}).json()
    for r in records:
        line(
            "TRACE",
            f"{r['action']['upstream']}.{r['action']['tool']:<14} "
            f"{r['decision']['effect']:<16} ({r['decision']['source']}) -> {r['result']['status']}",
        )

    print("\nSummary: the agent authenticated with its own key, acted under Sam's delegation,")
    print("was policy-checked and metered on every call, waited for a human on the risky one,")
    print("never touched a real credential, and left a tamper-evident trail.\n")

    for server in servers:
        server.should_exit = True


if __name__ == "__main__":
    main()
