"""Operator identity (C2): roles, attribution, break-glass, and the simulator."""

from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.server import create_app, create_app_context


class Env:
    def __init__(self) -> None:
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url="http://testserver",
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": True}))
            ),
        )
        self.client = TestClient(create_app(self.ctx))
        self.breakglass = {"x-toolgate-admin-key": self.ctx.config.admin_key}

        self.owner_key = self._create_operator("root", "owner")["key"]
        self.approver_key = self._create_operator("helpdesk", "approver")["key"]
        self.auditor_key = self._create_operator("compliance", "auditor")["key"]

        self.tenant = self.post(
            "/v1/control/tenants", {"name": "Acme"}, self.owner_key
        ).json()["id"]

    def _create_operator(self, name: str, role: str) -> dict[str, Any]:
        res = self.client.post(
            "/v1/control/operators", headers=self.breakglass, json={"name": name, "role": role}
        )
        assert res.status_code == 201, res.text
        return res.json()

    def headers(self, key: str | None) -> dict[str, str]:
        if key is None:
            return self.breakglass
        return {"x-toolgate-operator-key": key}

    def post(self, path: str, body: dict[str, Any], key: str | None) -> httpx.Response:
        return self.client.post(path, headers=self.headers(key), json=body)

    def get(self, path: str, key: str | None) -> httpx.Response:
        return self.client.get(path, headers=self.headers(key))


@pytest.fixture(scope="module")
def env() -> Env:
    return Env()


def test_operator_key_shown_once_and_hash_stored(env: Env) -> None:
    created = env._create_operator("temp", "auditor")
    assert created["key"].startswith("opk_")
    assert "keyHash" not in created["operator"]
    listed = env.get("/v1/control/operators", env.auditor_key).json()
    assert all("keyHash" not in o for o in listed)


def test_roles_enforced(env: Env) -> None:
    # Auditor: read yes, mutate no.
    assert env.get("/v1/control/tenants", env.auditor_key).status_code == 200
    denied = env.post("/v1/control/tenants", {"name": "Nope"}, env.auditor_key)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "TG_DENIED"

    # Approver: can read, cannot create tenants, CAN decide approvals (see below).
    assert env.post("/v1/control/tenants", {"name": "Nope"}, env.approver_key).status_code == 403

    # Owner: full mutation rights.
    assert env.post("/v1/control/tenants", {"name": "Ok"}, env.owner_key).status_code == 201

    # Unknown key: 401.
    bad = env.post("/v1/control/tenants", {"name": "x"}, "opk_wrong")
    assert bad.status_code == 401


def test_disabled_operator_locked_out(env: Env) -> None:
    created = env._create_operator("leaver", "owner")
    op_id, key = created["operator"]["id"], created["key"]
    assert env.post("/v1/control/tenants", {"name": "T"}, key).status_code == 201
    assert env.post(f"/v1/control/operators/{op_id}/disable", {}, env.owner_key).status_code == 200
    assert env.post("/v1/control/tenants", {"name": "T2"}, key).status_code == 401


def test_mutations_attributed_in_audit_chain(env: Env) -> None:
    env.post("/v1/control/users", {"tenantId": env.tenant, "displayName": "Sam"}, env.owner_key)
    records = env.ctx.store.list_audit()
    op_records = [r for r in records if r.decision.source == "operator"]
    assert op_records, "control-plane mutations must audit"
    last = op_records[-1]
    assert last.actor.agentId == "control-plane"
    assert last.actor.userId.startswith("op_")
    assert last.action.upstream == "control"
    # Break-glass usage is attributed to the sentinel operator id.
    env.post("/v1/control/tenants", {"name": "Glass"}, None)
    assert env.ctx.store.list_audit()[-1].actor.userId == "op_breakglass"
    # And the chain (now interleaving gate + ops records) still verifies.
    assert env.get("/v1/control/audit/verify", env.auditor_key).json()["valid"] is True


def test_simulator_dry_runs_policy(env: Env) -> None:
    policy = env.post(
        "/v1/control/policies",
        {
            "tenantId": env.tenant,
            "name": "sim",
            "rules": [
                {
                    "id": "tainted-guard",
                    "effect": "require_approval",
                    "match": {"tool": "send_email"},
                    "when": {"txnTouchedUntrusted": True},
                },
                {"id": "ok", "effect": "allow", "match": {"upstream": "crm"}},
            ],
        },
        env.owner_key,
    ).json()["id"]

    sim = lambda body: env.post(  # noqa: E731
        f"/v1/control/policies/{policy}/simulate", body, env.auditor_key
    ).json()

    assert sim({"upstream": "crm", "tool": "read"})["effect"] == "allow"
    assert sim({"upstream": "billing", "tool": "charge"})["effect"] == "deny"
    clean = sim({"upstream": "email", "tool": "send_email", "tainted": False})
    tainted = sim({"upstream": "email", "tool": "send_email", "tainted": True})
    assert clean["effect"] == "deny"  # default deny: no rule matches untainted email
    assert tainted["effect"] == "require_approval"
    assert tainted["ruleId"] == "tainted-guard"
    # Simulation must not write audit records or touch budgets.
    before = len(env.ctx.store.list_audit())
    sim({"upstream": "crm", "tool": "read"})
    assert len(env.ctx.store.list_audit()) == before
