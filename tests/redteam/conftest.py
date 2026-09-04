"""Red-team fixtures. Each attack module states its adversary model — what the
attacker holds — and asserts the system's containment guarantees (#9)."""

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


class Target:
    """A seeded Toolgate deployment under attack."""

    def __init__(self, taint_scope: str = "txn") -> None:
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=PUBLIC_URL,
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": 1}))
            ),
        )
        if taint_scope != "txn":
            import dataclasses

            self.ctx.config = dataclasses.replace(self.ctx.config, taint_scope=taint_scope)
        self.app = create_app(self.ctx)
        self.client = TestClient(self.app)
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}
        self.agent_keys = generate_ed25519_key_pair()

        self.tenant = self.post("/v1/control/tenants", {"name": "Victim Corp"})["id"]
        self.user = self.post(
            "/v1/control/users", {"tenantId": self.tenant, "displayName": "Sam"}
        )["id"]
        self.agent = self.post(
            "/v1/control/agents",
            {"tenantId": self.tenant, "name": "assistant", "publicJwk": self.agent_keys.public_jwk},
        )["id"]
        self.post(
            "/v1/control/upstreams",
            {
                "tenantId": self.tenant,
                "name": "web",
                "baseUrl": "https://web.internal",
                "credential": {"mode": "bearer", "secret": "web-key"},
                "tools": [{"name": "browse", "contentTrust": "untrusted_source"}],
            },
        )
        self.post(
            "/v1/control/upstreams",
            {
                "tenantId": self.tenant,
                "name": "email",
                "baseUrl": "https://mail.internal",
                "credential": {"mode": "bearer", "secret": "mail-key"},
                "tools": [{"name": "send_email", "sideEffecting": True}],
            },
        )
        self.policy = self.post(
            "/v1/control/policies",
            {
                "tenantId": self.tenant,
                "name": "p",
                "rules": [
                    {
                        "id": "tainted-guard",
                        "effect": "require_approval",
                        "match": {"tool": "send_email"},
                        "when": {"txnTouchedUntrusted": True},
                    },
                    {"id": "allow", "effect": "allow", "match": {}},
                ],
            },
        )["id"]

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def grant(self, budget: int = 30, authz: list | None = None) -> str:
        return self.post(
            "/v1/control/grants",
            {
                "tenantId": self.tenant,
                "userId": self.user,
                "agentId": self.agent,
                "policyId": self.policy,
                "authorization": authz
                or [{"upstream": "web", "tools": ["*"]}, {"upstream": "email", "tools": ["*"]}],
                "budgetMaxUnits": budget,
            },
        )["id"]

    def token(self, grant: str) -> str:
        assertion = sign_client_assertion(
            self.agent_keys.private_jwk, agent_id=self.agent, token_url=f"{PUBLIC_URL}/v1/token"
        )
        res = self.client.post(
            "/v1/token",
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_assertion": assertion,
                "grant_id": grant,
            },
        )
        assert res.status_code == 200, res.text
        return res.json()["access_token"]

    def signed_call(
        self, token: str, upstream: str, tool: str, args: dict | None = None
    ) -> httpx.Response:
        """A legitimate agent call (attacker also holds the key)."""
        path = f"/v1/gate/call/{upstream}"
        body = json.dumps({"tool": tool, "args": args or {}}).encode()
        proof = sign_pop_proof(
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

    def mcp_call(self, token: str, message: dict) -> httpx.Response:
        """Token-only surface: what a thief with just the bearer token can use."""
        return self.client.post(
            "/v1/mcp", headers={"authorization": f"Bearer {token}"}, json=message
        )


@pytest.fixture()
def target() -> Target:
    return Target()


@pytest.fixture()
def grant_scoped_target() -> Target:
    return Target(taint_scope="grant")
