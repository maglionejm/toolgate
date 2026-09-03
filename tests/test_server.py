import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import (
    generate_ed25519_key_pair,
    sign_client_assertion,
    sign_pop_proof,
)
from toolgate.server import create_app, create_app_context

PUBLIC_URL = "http://testserver"


class Env:
    """Shared scenario state; tests run in definition order and accumulate
    budget spend exactly like the original TS suite."""

    def __init__(self) -> None:
        self.upstream_calls: list[dict[str, Any]] = []

        def upstream_handler(request: httpx.Request) -> httpx.Response:
            self.upstream_calls.append(
                {
                    "url": str(request.url),
                    "headers": dict(request.headers),
                    "body": json.loads(request.content) if request.content else None,
                }
            )
            return httpx.Response(200, json={"ok": True})

        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=PUBLIC_URL,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler)),
        )
        self.client = TestClient(create_app(self.ctx))
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}
        self.agent_keys = generate_ed25519_key_pair()

        self.tenant_id = self.admin_post("/v1/control/tenants", {"name": "Acme"})["id"]
        self.user_id = self.admin_post(
            "/v1/control/users",
            {"tenantId": self.tenant_id, "displayName": "Sam", "email": "sam@acme.com"},
        )["id"]
        self.agent_id = self.admin_post(
            "/v1/control/agents",
            {
                "tenantId": self.tenant_id,
                "name": "assistant",
                "publicJwk": self.agent_keys.public_jwk,
            },
        )["id"]

        self.admin_post(
            "/v1/control/upstreams",
            {
                "tenantId": self.tenant_id,
                "name": "crm",
                "baseUrl": "https://crm.internal",
                "credential": {"mode": "bearer", "secret": "crm-secret-123"},
                "tools": [
                    {"name": "read_contact", "costUnits": 1},
                    {"name": "delete_contact", "sideEffecting": True, "costUnits": 1},
                ],
            },
        )
        self.admin_post(
            "/v1/control/upstreams",
            {
                "tenantId": self.tenant_id,
                "name": "email",
                "baseUrl": "https://mail.internal",
                "credential": {"mode": "header", "headerName": "X-Api-Key", "secret": "mail-456"},
                "tools": [{"name": "send_email", "sideEffecting": True, "costUnits": 2}],
            },
        )

        self.policy_id = self.admin_post(
            "/v1/control/policies",
            {
                "tenantId": self.tenant_id,
                "name": "default",
                "rules": [
                    {
                        "id": "no-deletes",
                        "effect": "deny",
                        "match": {"upstream": "crm", "tool": "delete_*"},
                    },
                    {
                        "id": "approve-external-email",
                        "effect": "require_approval",
                        "match": {
                            "upstream": "email",
                            "tool": "send_email",
                            "where": [{"path": "to", "op": "matches", "value": "@(?!acme\\.com$)"}],
                        },
                    },
                    {
                        "id": "allow-email",
                        "effect": "allow",
                        "match": {"upstream": "email", "tool": "send_email"},
                    },
                    {
                        "id": "allow-crm",
                        "effect": "allow",
                        "match": {"upstream": "crm", "tool": "*"},
                    },
                ],
            },
        )["id"]

        self.grant_id = self.admin_post(
            "/v1/control/grants",
            {
                "tenantId": self.tenant_id,
                "userId": self.user_id,
                "agentId": self.agent_id,
                "policyId": self.policy_id,
                "scopes": ["crm:read", "email:send"],
                "authorization": [
                    {"upstream": "crm", "tools": ["*"]},
                    {"upstream": "email", "tools": ["send_email"]},
                ],
                "budgetMaxUnits": 7,
            },
        )["id"]

    def admin_post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, f"POST {path} -> {res.status_code}: {res.text}"
        return res.json()

    def get_token(self) -> str:
        assertion = sign_client_assertion(
            self.agent_keys.private_jwk,
            agent_id=self.agent_id,
            token_url=f"{PUBLIC_URL}/v1/token",
        )
        res = self.client.post(
            "/v1/token",
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_assertion": assertion,
                "grant_id": self.grant_id,
            },
        )
        assert res.status_code == 200, res.text
        return res.json()["access_token"]

    def gate_call(
        self, token: str, upstream: str, tool: str, args: dict[str, Any], proof: str | None = None
    ) -> httpx.Response:
        path = f"/v1/gate/call/{upstream}"
        body = json.dumps({"tool": tool, "args": args}).encode()
        proof = proof or sign_pop_proof(
            self.agent_keys.private_jwk,
            htm="POST",
            htu=f"{PUBLIC_URL}{path}",
            access_token=token,
            body=body,
        )
        return self.client.post(
            path,
            headers={
                "authorization": f"Bearer {token}",
                "x-toolgate-proof": proof,
                "content-type": "application/json",
            },
            content=body,
        )

    def execute_approval(self, token: str, approval_id: str) -> httpx.Response:
        path = f"/v1/gate/approvals/{approval_id}/execute"
        proof = sign_pop_proof(
            self.agent_keys.private_jwk,
            htm="POST",
            htu=f"{PUBLIC_URL}{path}",
            access_token=token,
        )
        return self.client.post(
            path, headers={"authorization": f"Bearer {token}", "x-toolgate-proof": proof}
        )


@pytest.fixture(scope="module")
def env() -> Env:
    return Env()


def test_allowed_call_injects_credential(env: Env) -> None:
    token = env.get_token()
    res = env.gate_call(token, "crm", "read_contact", {"contactId": "c1"})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "executed"
    assert body["result"]["ok"] is True

    upstream = env.upstream_calls[-1]
    assert upstream["url"] == "https://crm.internal/tools/read_contact"
    assert upstream["headers"]["authorization"] == "Bearer crm-secret-123"
    assert upstream["body"] == {"contactId": "c1"}


def test_credential_never_leaks_to_agent(env: Env) -> None:
    token = env.get_token()
    res = env.gate_call(token, "crm", "read_contact", {"contactId": "c2"})
    assert "crm-secret-123" not in res.text


def test_policy_denial_is_audited(env: Env) -> None:
    token = env.get_token()
    res = env.gate_call(token, "crm", "delete_contact", {"contactId": "c1"})
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "TG_DENIED"

    denial = env.ctx.store.list_audit(env.tenant_id)[-1]
    assert denial.decision.effect == "deny"
    assert denial.result.status == "denied"
    assert denial.action.tool == "delete_contact"


def test_proof_replay_rejected(env: Env) -> None:
    token = env.get_token()
    path = "/v1/gate/call/crm"
    body = json.dumps({"tool": "read_contact", "args": {}}).encode()
    proof = sign_pop_proof(
        env.agent_keys.private_jwk,
        htm="POST",
        htu=f"{PUBLIC_URL}{path}",
        access_token=token,
        body=body,
    )
    first = env.gate_call(token, "crm", "read_contact", {}, proof=proof)
    assert first.status_code == 200
    replay = env.gate_call(token, "crm", "read_contact", {}, proof=proof)
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "TG_PROOF_INVALID"


def test_assertion_replay_rejected(env: Env) -> None:
    assertion = sign_client_assertion(
        env.agent_keys.private_jwk, agent_id=env.agent_id, token_url=f"{PUBLIC_URL}/v1/token"
    )
    body = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion": assertion,
        "grant_id": env.grant_id,
    }
    assert env.client.post("/v1/token", json=body).status_code == 200
    assert env.client.post("/v1/token", json=body).status_code == 401


def test_approval_flow_binds_args(env: Env) -> None:
    token = env.get_token()
    res = env.gate_call(
        token, "email", "send_email", {"to": "ceo@bigcorp.com", "subject": "Q3 numbers"}
    )
    assert res.status_code == 202
    approval_id = res.json()["approval_id"]

    poll_path = f"/v1/gate/approvals/{approval_id}"
    poll_proof = sign_pop_proof(
        env.agent_keys.private_jwk,
        htm="GET",
        htu=f"{PUBLIC_URL}{poll_path}",
        access_token=token,
    )
    poll = env.client.get(
        poll_path,
        headers={"authorization": f"Bearer {token}", "x-toolgate-proof": poll_proof},
    )
    assert poll.json()["status"] == "pending"

    early = env.execute_approval(token, approval_id)
    assert early.status_code == 409

    decided = env.admin_post(
        f"/v1/control/approvals/{approval_id}/decide",
        {"decision": "approve", "decidedBy": env.user_id},
    )
    assert decided["status"] == "approved"

    executed = env.execute_approval(token, approval_id)
    assert executed.status_code == 200
    upstream = env.upstream_calls[-1]
    assert upstream["url"] == "https://mail.internal/tools/send_email"
    assert upstream["headers"]["x-api-key"] == "mail-456"
    assert upstream["body"] == {"to": "ceo@bigcorp.com", "subject": "Q3 numbers"}

    again = env.execute_approval(token, approval_id)
    assert again.status_code == 403


def test_budget_exhaustion(env: Env) -> None:
    # Budget 7: spent so far read(1)+read(1)+read(1)+email(2) = 5. Two units left.
    token = env.get_token()
    assert env.gate_call(token, "crm", "read_contact", {"n": 1}).status_code == 200
    assert env.gate_call(token, "crm", "read_contact", {"n": 2}).status_code == 200
    broke = env.gate_call(token, "crm", "read_contact", {"n": 3})
    assert broke.status_code == 403
    assert broke.json()["error"]["code"] == "TG_BUDGET_EXCEEDED"


def test_revocation_kills_live_tokens(env: Env) -> None:
    token = env.get_token()
    env.admin_post(f"/v1/control/grants/{env.grant_id}/revoke", {})
    res = env.gate_call(token, "crm", "read_contact", {"n": 9})
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "TG_REVOKED"


def test_audit_chain_verifies(env: Env) -> None:
    res = env.client.get("/v1/control/audit/verify", headers=env.admin)
    body = res.json()
    assert body["valid"] is True
    assert body["length"] >= 8


def test_control_plane_requires_admin_key(env: Env) -> None:
    assert env.client.get("/v1/control/audit").status_code == 401
