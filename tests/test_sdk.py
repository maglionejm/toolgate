import threading
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import generate_ed25519_key_pair
from toolgate.sdk import PendingApproval, ToolgateCallError, ToolgateClient
from toolgate.server import create_app, create_app_context

BASE = "http://testserver"


class Env:
    def __init__(self) -> None:
        self.token_exchanges = 0
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=BASE,
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _req: httpx.Response(200, json={"ok": True}))
            ),
        )
        app = create_app(self.ctx)
        self.http = TestClient(app)
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}
        agent_keys = generate_ed25519_key_pair()

        tenant_id = self._post("/v1/control/tenants", {"name": "Acme"})["id"]
        self.user_id = self._post(
            "/v1/control/users", {"tenantId": tenant_id, "displayName": "Sam"}
        )["id"]
        agent_id = self._post(
            "/v1/control/agents",
            {"tenantId": tenant_id, "name": "assistant", "publicJwk": agent_keys.public_jwk},
        )["id"]
        self._post(
            "/v1/control/upstreams",
            {
                "tenantId": tenant_id,
                "name": "crm",
                "baseUrl": "https://crm.internal",
                "credential": {"mode": "bearer", "secret": "s3cret"},
                "tools": [
                    {"name": "read_contact", "costUnits": 1},
                    {"name": "wire_money", "sideEffecting": True, "costUnits": 1},
                    {"name": "drop_database", "sideEffecting": True, "costUnits": 1},
                ],
            },
        )
        policy_id = self._post(
            "/v1/control/policies",
            {
                "tenantId": tenant_id,
                "name": "default",
                "rules": [
                    {"effect": "deny", "match": {"tool": "drop_*"}},
                    {"effect": "require_approval", "match": {"tool": "wire_money"}},
                    {"effect": "allow", "match": {"upstream": "crm"}},
                ],
            },
        )["id"]
        grant_id = self._post(
            "/v1/control/grants",
            {
                "tenantId": tenant_id,
                "userId": self.user_id,
                "agentId": agent_id,
                "policyId": policy_id,
                "authorization": [{"upstream": "crm", "tools": ["*"]}],
                "budgetMaxUnits": 100,
            },
        )["id"]

        # Count token exchanges by wrapping the TestClient's request method.
        env = self

        class CountingClient(httpx.Client):
            def request(self, method: str, url: Any, **kwargs: Any) -> httpx.Response:
                if str(url).endswith("/v1/token"):
                    env.token_exchanges += 1
                return env.http.request(method, url, **kwargs)

        self.client = ToolgateClient(
            base_url=BASE,
            agent_id=agent_id,
            agent_private_jwk=agent_keys.private_jwk,
            grant_id=grant_id,
            http_client=CountingClient(),
        )

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.http.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def decide(self, approval_id: str, decision: str, delay: float) -> threading.Timer:
        def apply() -> None:
            approval = self.ctx.store.get_approval(approval_id)
            assert approval is not None
            approval.status = "approved" if decision == "approve" else "denied"
            approval.decidedAt = datetime.now(UTC).isoformat()
            approval.decidedBy = self.user_id
            self.ctx.store.put_approval(approval)

        timer = threading.Timer(delay, apply)
        timer.start()
        return timer


@pytest.fixture(scope="module")
def env() -> Env:
    return Env()


def test_executes_and_reuses_cached_token(env: Env) -> None:
    first = env.client.call("crm", "read_contact", {"id": "c1"})
    second = env.client.call("crm", "read_contact", {"id": "c2"})
    assert first.status == "executed"
    assert second.status == "executed"
    assert env.token_exchanges == 1


def test_typed_error_on_denial(env: Env) -> None:
    with pytest.raises(ToolgateCallError) as err:
        env.client.call("crm", "drop_database")
    assert err.value.code == "TG_DENIED"
    assert err.value.http_status == 403


def test_full_approval_flow(env: Env) -> None:
    parked = env.client.call("crm", "wire_money", {"amount": 100, "to": "ACME-42"})
    assert isinstance(parked, PendingApproval)

    timer = env.decide(parked.approval_id, "approve", delay=0.3)
    executed = env.client.wait_for_approval(parked.approval_id, poll_seconds=0.1)
    timer.join()
    assert executed.status == "executed"
    assert executed.result["ok"] is True


def test_denial_while_waiting(env: Env) -> None:
    parked = env.client.call("crm", "wire_money", {"amount": 999999, "to": "SHELL-CO"})
    assert isinstance(parked, PendingApproval)

    timer = env.decide(parked.approval_id, "deny", delay=0.2)
    with pytest.raises(ToolgateCallError) as err:
        env.client.wait_for_approval(parked.approval_id, poll_seconds=0.1)
    timer.join()
    assert err.value.code == "TG_APPROVAL_DENIED"
