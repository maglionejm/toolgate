"""PR C surfaces: MCP layer (B1), async SDK + adapters (B3), reports (B5)."""

import asyncio
import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import generate_ed25519_key_pair, sign_client_assertion
from toolgate.integrations import anthropic_tools, openai_tools
from toolgate.sdk import AsyncToolgateClient, PendingApproval, ToolgateClient
from toolgate.server import create_app, create_app_context

BASE = "http://testserver"


class Env:
    def __init__(self) -> None:
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=BASE,
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": 1}))
            ),
        )
        self.app = create_app(self.ctx)
        self.client = TestClient(self.app)
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}
        self.agent_keys = generate_ed25519_key_pair()

        self.tenant = self._post("/v1/control/tenants", {"name": "Acme"})["id"]
        self.user = self._post(
            "/v1/control/users", {"tenantId": self.tenant, "displayName": "Sam"}
        )["id"]
        self.agent = self._post(
            "/v1/control/agents",
            {"tenantId": self.tenant, "name": "a", "publicJwk": self.agent_keys.public_jwk},
        )["id"]
        self._post(
            "/v1/control/upstreams",
            {
                "tenantId": self.tenant,
                "name": "crm",
                "baseUrl": "https://crm.internal",
                "credential": {"mode": "bearer", "secret": "k"},
                "tools": [
                    {
                        "name": "read_contact",
                        "description": "Read one contact",
                        "costUnits": 1,
                        "argsSchema": {
                            "type": "object",
                            "properties": {"contactId": {"type": "string"}},
                            "required": ["contactId"],
                        },
                    },
                    {"name": "wire_money", "sideEffecting": True, "costUnits": 2},
                    {"name": "drop_db", "sideEffecting": True},
                ],
            },
        )
        self.policy = self._post(
            "/v1/control/policies",
            {
                "tenantId": self.tenant,
                "name": "p",
                "rules": [
                    {"id": "no-drop", "effect": "deny", "match": {"tool": "drop_*"}},
                    {"id": "human-wire", "effect": "require_approval",
                     "match": {"tool": "wire_money"}},
                    {"id": "ok", "effect": "allow", "match": {"upstream": "crm"}},
                ],
            },
        )["id"]
        self.grant = self._post(
            "/v1/control/grants",
            {
                "tenantId": self.tenant,
                "userId": self.user,
                "agentId": self.agent,
                "policyId": self.policy,
                "authorization": [{"upstream": "crm", "tools": ["read_contact", "wire_money"]}],
                "budgetMaxUnits": 40,
            },
        )["id"]

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def token(self) -> str:
        assertion = sign_client_assertion(
            self.agent_keys.private_jwk, agent_id=self.agent, token_url=f"{BASE}/v1/token"
        )
        res = self.client.post(
            "/v1/token",
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_assertion": assertion,
                "grant_id": self.grant,
            },
        )
        assert res.status_code == 200
        return res.json()["access_token"]

    def mcp(self, method: str, params: dict | None = None, req_id: int | None = 1) -> Any:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if req_id is not None:
            message["id"] = req_id
        if params is not None:
            message["params"] = params
        return self.client.post(
            "/v1/mcp",
            headers={"authorization": f"Bearer {self.token()}"},
            json=message,
        )

    def sync_client(self) -> ToolgateClient:
        class Bridge(httpx.Client):
            def request(inner, method: str, url: Any, **kw: Any) -> httpx.Response:  # noqa: N805
                return self.client.request(method, str(url), **kw)

        return ToolgateClient(
            base_url=BASE,
            agent_id=self.agent,
            agent_private_jwk=self.agent_keys.private_jwk,
            grant_id=self.grant,
            http_client=Bridge(),
        )


@pytest.fixture(scope="module")
def env() -> Env:
    return Env()


# --- B1: MCP -------------------------------------------------------------------


def test_mcp_initialize_and_list(env: Env) -> None:
    init = env.mcp("initialize", {"protocolVersion": "2025-06-18"}).json()
    assert init["result"]["serverInfo"]["name"] == "toolgate"

    tools = env.mcp("tools/list").json()["result"]["tools"]
    names = {t["name"] for t in tools}
    # Discovery is bounded by authorization_details: drop_db is not delegated.
    assert names == {"crm__read_contact", "crm__wire_money"}
    read = next(t for t in tools if t["name"] == "crm__read_contact")
    assert read["inputSchema"]["required"] == ["contactId"]


def test_mcp_call_executes_through_pipeline(env: Env) -> None:
    res = env.mcp(
        "tools/call", {"name": "crm__read_contact", "arguments": {"contactId": "c1"}}
    ).json()
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload == {"ok": 1}
    # The call went through the same audited pipeline.
    last = env.ctx.store.list_audit(env.tenant)[-1]
    assert last.action.tool == "read_contact" and last.result.status == "executed"


def test_mcp_denial_and_approval_surface_as_rpc_errors(env: Env) -> None:
    denied = env.mcp("tools/call", {"name": "crm__drop_db", "arguments": {}}).json()
    assert denied["error"]["code"] == -32010
    assert denied["error"]["data"]["code"] == "TG_DENIED"

    parked = env.mcp("tools/call", {"name": "crm__wire_money", "arguments": {"amt": 1}}).json()
    assert parked["error"]["code"] == -32009
    assert parked["error"]["data"]["approval_id"].startswith("apr_")


def test_mcp_notifications_get_202(env: Env) -> None:
    res = env.mcp("notifications/initialized", req_id=None)
    assert res.status_code == 202


# --- B3: async SDK + adapters -----------------------------------------------------


def test_async_sdk_end_to_end(env: Env) -> None:
    async def run() -> None:
        transport = httpx.ASGITransport(app=env.app)
        client = AsyncToolgateClient(
            base_url=BASE,
            agent_id=env.agent,
            agent_private_jwk=env.agent_keys.private_jwk,
            grant_id=env.grant,
            http_client=httpx.AsyncClient(transport=transport, base_url=BASE),
        )
        tools = await client.list_tools()
        assert {t["name"] for t in tools} == {"read_contact", "wire_money"}

        done = await client.call("crm", "read_contact", {"contactId": "c9"})
        assert done.status == "executed"

        parked = await client.call("crm", "wire_money", {"amount": 5})
        assert isinstance(parked, PendingApproval)
        assert await client.approval_status(parked.approval_id) == "pending"

    asyncio.run(run())


def test_openai_adapter_schema_and_dispatch(env: Env) -> None:
    tools, dispatch = openai_tools(env.sync_client())
    names = {t["function"]["name"] for t in tools}
    assert names == {"crm__read_contact", "crm__wire_money"}

    out = dispatch("crm__read_contact", {"contactId": "c2"})
    assert out == {"status": "executed", "result": {"ok": 1}}
    parked = dispatch("crm__wire_money", {"amount": 9})
    assert parked["status"] == "pending_approval"
    assert dispatch("bad-name", {})["error"].startswith("tool name must be")


def test_anthropic_adapter_schema_and_dispatch(env: Env) -> None:
    tools, dispatch = anthropic_tools(env.sync_client())
    by_name = {t["name"]: t for t in tools}
    assert set(by_name) == {"crm__read_contact", "crm__wire_money"}
    # Declared schemas pass through; tools without one get an open object schema.
    assert by_name["crm__read_contact"]["input_schema"]["required"] == ["contactId"]
    assert by_name["crm__wire_money"]["input_schema"]["type"] == "object"

    out = dispatch("crm__read_contact", {"contactId": "c3"})
    assert out == {"status": "executed", "result": {"ok": 1}}
    parked = dispatch("crm__wire_money", {"amount": 9})
    assert parked["status"] == "pending_approval"
    assert dispatch("bad-name", {})["error"].startswith("tool name must be")


# --- B5: reports --------------------------------------------------------------------


def test_reports_rollup(env: Env) -> None:
    report = env.client.get(
        f"/v1/control/reports?tenantId={env.tenant}", headers=env.admin
    ).json()
    tot = report["totals"]
    assert tot["calls"] == tot["executed"] + tot["denied"] + tot["pendingApproval"] + tot["errors"]
    assert tot["executed"] >= 3 and tot["denied"] >= 1 and tot["pendingApproval"] >= 3
    read_row = next(r for r in report["byTool"] if r["tool"] == "crm.read_contact")
    assert read_row["executed"] == read_row["calls"]
    assert read_row["costUnits"] == read_row["executed"]  # cost 1 per call
    agent_row = next(r for r in report["byAgent"] if r["agentId"] == env.agent)
    assert agent_row["calls"] == tot["calls"]
