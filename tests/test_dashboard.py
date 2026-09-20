"""Operator dashboard endpoint + projection (spec: add-operator-dashboard).

Hermetic: upstream traffic goes through an httpx MockTransport and dashboard
reads through the FastAPI TestClient. Windowing and bucketing determinism is
unit-tested against build_dashboard with an injected `now`.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import (
    ApprovalRequest,
    AuditAction,
    AuditActor,
    AuditDecision,
    AuditRecordInput,
    AuditResult,
    Delivery,
    generate_ed25519_key_pair,
    new_id,
)
from toolgate.sdk import PendingApproval, ToolgateCallError, ToolgateClient
from toolgate.server import create_app, create_app_context
from toolgate.server.dashboard import build_dashboard

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
                    {"name": "read_contact", "costUnits": 1},
                    {"name": "wire_money", "sideEffecting": True, "costUnits": 2},
                    {"name": "drop_table", "sideEffecting": True, "costUnits": 1},
                ],
            },
        )
        self.policy = self._post(
            "/v1/control/policies",
            {
                "tenantId": self.tenant,
                "name": "p",
                "rules": [
                    {"id": "no-drop", "effect": "deny", "match": {"tool": "drop_table"}},
                    {"id": "human-wire", "effect": "require_approval",
                     "match": {"tool": "wire_money"}},
                    {"id": "ok", "effect": "allow", "match": {}},
                ],
            },
        )["id"]
        self.grant = self.make_grant(budget=40)

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def make_grant(self, budget: int) -> str:
        return self._post(
            "/v1/control/grants",
            {
                "tenantId": self.tenant,
                "userId": self.user,
                "agentId": self.agent,
                "policyId": self.policy,
                "authorization": [{"upstream": "crm", "tools": ["*"]}],
                "budgetMaxUnits": budget,
            },
        )["id"]

    def sdk(
        self,
        grant_id: str | None = None,
        *,
        agent_id: str | None = None,
        private_jwk: dict[str, Any] | None = None,
    ) -> ToolgateClient:
        outer = self

        class Bridge(httpx.Client):
            def request(inner, method: str, url: Any, **kw: Any) -> httpx.Response:  # noqa: N805
                return outer.client.request(method, str(url), **kw)

        return ToolgateClient(
            base_url=BASE,
            agent_id=agent_id or self.agent,
            agent_private_jwk=private_jwk or self.agent_keys.private_jwk,
            grant_id=grant_id or self.grant,
            http_client=Bridge(),
        )

    def dashboard(self, tenant: str | None = None, **params: Any) -> dict[str, Any]:
        res = self.client.get(
            "/v1/control/dashboard",
            headers=self.admin,
            params={"tenantId": tenant or self.tenant, **params},
        )
        assert res.status_code == 200, res.text
        return res.json()


@pytest.fixture()
def env() -> Env:
    return Env()


def _seed_activity(env: Env) -> None:
    """Real gated traffic: 3 executed, 1 denied (policy), 1 parked (approval)."""
    sdk = env.sdk()
    for _ in range(3):
        sdk.call("crm", "read_contact", {"id": "c1"})
    with pytest.raises(ToolgateCallError):
        sdk.call("crm", "drop_table", {"table": "users"})
    parked = sdk.call("crm", "wire_money", {"amount": 99, "to": "acct-7"})
    assert isinstance(parked, PendingApproval)


def _gate_record(
    env: Env,
    ts: datetime,
    status: str = "executed",
    cost: int | None = 1,
    tool: str = "read_contact",
) -> None:
    """Append a gate-call audit record with a controlled timestamp."""
    env.ctx.audit.record(
        AuditRecordInput(
            id=new_id("evt"),
            tenantId=env.tenant,
            ts=ts.isoformat(),
            actor=AuditActor(
                agentId="agt_test", userId="usr_test", grantId="grt_test", tokenJti="-"
            ),
            action=AuditAction(
                callId=new_id("call"), upstream="crm", tool=tool, argsHash="0" * 64
            ),
            decision=AuditDecision(effect="allow", source="rule", reason="test"),
            result=AuditResult(
                status=status,  # type: ignore[arg-type]
                costUnits=cost if status == "executed" else None,
            ),
        )
    )


# --- shape and contents ----------------------------------------------------------------


def test_dashboard_shape_after_real_calls(env: Env) -> None:
    _seed_activity(env)
    grant2 = env.make_grant(budget=4)
    env.sdk(grant2).call("crm", "read_contact", {"id": "c2"})

    body = env.dashboard()
    assert body["tenantId"] == env.tenant

    window = body["window"]
    assert window["hours"] == 24
    assert window["bucketSeconds"] == 24 * 75
    span = datetime.fromisoformat(window["to"]) - datetime.fromisoformat(window["from"])
    assert span == timedelta(hours=24)

    assert body["totals"] == {
        "calls": 6, "executed": 4, "denied": 1, "parked": 1, "errors": 0,
        "costUnits": 4, "activeAgents": 1,
    }

    series = body["series"]
    assert len(series) == 48
    sums = [sum(b[k] for b in series) for k in ("executed", "denied", "parked", "errors")]
    assert sums == [4, 1, 1, 0]
    starts = [datetime.fromisoformat(b["start"]) for b in series]
    assert starts[0] == datetime.fromisoformat(window["from"])
    step = timedelta(seconds=window["bucketSeconds"])
    assert all(b - a == step for a, b in zip(starts, starts[1:], strict=False))

    # calls desc, then tool asc for the tie between drop_table and wire_money.
    assert body["topTools"] == [
        {"tool": "crm.read_contact", "calls": 4, "denied": 0},
        {"tool": "crm.drop_table", "calls": 1, "denied": 1},
        {"tool": "crm.wire_money", "calls": 1, "denied": 0},
    ]

    # grant2 utilization 1/4 outranks grant1's 3/40 (parked and denied calls
    # never charged the budget).
    budgets = body["budgets"]
    assert [b["grantId"] for b in budgets] == [grant2, env.grant]
    assert budgets[0] == {
        "grantId": grant2, "agentId": env.agent, "spentUnits": 1, "maxUnits": 4,
        "status": "active",
    }
    assert budgets[1]["spentUnits"] == 3 and budgets[1]["maxUnits"] == 40

    approvals = body["approvals"]
    assert approvals["pending"] == 1
    assert isinstance(approvals["oldestPendingAgeSeconds"], int)
    assert approvals["oldestPendingAgeSeconds"] >= 0


def test_empty_tenant_zero_filled(env: Env) -> None:
    fresh = env._post("/v1/control/tenants", {"name": "Empty"})["id"]
    body = env.dashboard(tenant=fresh)
    assert body["tenantId"] == fresh
    assert body["totals"] == {
        "calls": 0, "executed": 0, "denied": 0, "parked": 0, "errors": 0,
        "costUnits": 0, "activeAgents": 0,
    }
    assert len(body["series"]) == 48
    assert all(
        b["executed"] == b["denied"] == b["parked"] == b["errors"] == 0
        for b in body["series"]
    )
    assert body["topTools"] == []
    assert body["budgets"] == []
    assert body["approvals"] == {"pending": 0, "oldestPendingAgeSeconds": None}
    operational = body["operational"]
    assert operational["anchoring"] == {
        "enabled": False, "anchored": 0, "total": 0, "degraded": False,
    }
    assert operational["deliveries"] == {"pending": 0, "delivered": 0, "failed": 0}
    assert operational["authFailures"] == {}


# --- windowing and bucketing (deterministic, injected now) ------------------------------


def test_windowing_and_bucketing_deterministic(env: Env) -> None:
    now = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)
    start = now - timedelta(hours=24)
    _gate_record(env, start, cost=5)                       # ts == from: included, bucket 0
    _gate_record(env, start - timedelta(seconds=1))        # just outside from: excluded
    _gate_record(env, now)                                 # ts == to: excluded
    _gate_record(env, now - timedelta(seconds=1), cost=2)  # just below to: clamped to 47

    body = build_dashboard(env.ctx, env.tenant, 24, now=now)
    assert body["window"]["from"] == start.isoformat()
    assert body["window"]["to"] == now.isoformat()
    assert body["window"]["bucketSeconds"] == 1800
    assert body["totals"]["calls"] == 2
    assert body["totals"]["executed"] == 2
    assert body["totals"]["costUnits"] == 7
    series = body["series"]
    assert series[0]["executed"] == 1
    assert series[47]["executed"] == 1
    assert sum(b["executed"] for b in series) == 2


# --- record selection -------------------------------------------------------------------


def test_control_plane_records_excluded(env: Env) -> None:
    control_records = [
        r for r in env.ctx.store.list_audit(env.tenant) if r.action.upstream == "control"
    ]
    assert control_records, "seeding must have produced control-plane ops-audit records"
    totals = env.dashboard()["totals"]
    assert totals["calls"] == 0
    assert totals["activeAgents"] == 0


def test_tenant_isolation(env: Env) -> None:
    other = env._post("/v1/control/tenants", {"name": "Other"})["id"]
    _seed_activity(env)
    assert env.dashboard()["totals"]["calls"] == 5
    body = env.dashboard(tenant=other)
    assert body["totals"]["calls"] == 0
    assert body["topTools"] == []
    assert body["budgets"] == []
    assert body["approvals"] == {"pending": 0, "oldestPendingAgeSeconds": None}


# --- gating and side effects ------------------------------------------------------------


def test_gating_matches_reports_and_unknown_tenant_404(env: Env) -> None:
    unauth_reports = env.client.get("/v1/control/reports", params={"tenantId": env.tenant})
    unauth_dashboard = env.client.get("/v1/control/dashboard", params={"tenantId": env.tenant})
    assert unauth_dashboard.status_code == unauth_reports.status_code == 401

    missing = env.client.get(
        "/v1/control/dashboard", headers=env.admin, params={"tenantId": "tnt_missing"}
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "TG_NOT_FOUND"


def test_dashboard_is_read_only(env: Env) -> None:
    _seed_activity(env)
    before = len(env.ctx.store.list_audit())
    env.dashboard()
    env.dashboard(hours=1)
    assert len(env.ctx.store.list_audit()) == before


# --- operational block ------------------------------------------------------------------


def test_operational_reflects_delivery_statuses(env: Env) -> None:
    now = datetime.now(UTC).isoformat()
    for i, status in enumerate(("pending", "delivered", "delivered", "failed")):
        env.ctx.store.put_delivery(
            Delivery(
                id=f"dlv_{i}",
                tenantId=env.tenant,
                channelId="chn_1",
                channelType="webhook",
                approvalId="apr_1",
                event="parked",
                status=status,  # type: ignore[arg-type]
                nextAttemptAt=now,
                createdAt=now,
                updatedAt=now,
            )
        )
    assert env.dashboard()["operational"]["deliveries"] == {
        "pending": 1, "delivered": 2, "failed": 1,
    }


# --- hours clamping ---------------------------------------------------------------------


def test_hours_clamping(env: Env) -> None:
    high = env.dashboard(hours=99999)
    assert high["window"]["hours"] == 168
    assert high["window"]["bucketSeconds"] == 168 * 75
    low = env.dashboard(hours=0)
    assert low["window"]["hours"] == 1
    assert low["window"]["bucketSeconds"] == 75
    negative = env.dashboard(hours=-5)
    assert negative["window"]["hours"] == 1


# --- adversarial: cross-tenant isolation across every dashboard section ------------------


def _provision_busy_tenant(env: Env) -> dict[str, Any]:
    """A second, busier tenant with its own agent, grants, parked approval, and
    delivery rows — everything a leak could surface through."""
    keys = generate_ed25519_key_pair()
    tenant = env._post("/v1/control/tenants", {"name": "Busy"})["id"]
    user = env._post("/v1/control/users", {"tenantId": tenant, "displayName": "Eve"})["id"]
    agent = env._post(
        "/v1/control/agents", {"tenantId": tenant, "name": "b", "publicJwk": keys.public_jwk}
    )["id"]
    env._post(
        "/v1/control/upstreams",
        {
            "tenantId": tenant,
            "name": "billing",
            "baseUrl": "https://billing.internal",
            "credential": {"mode": "bearer", "secret": "k"},
            "tools": [
                {"name": "charge", "costUnits": 3},
                {"name": "refund", "sideEffecting": True, "costUnits": 1},
            ],
        },
    )
    policy = env._post(
        "/v1/control/policies",
        {
            "tenantId": tenant,
            "name": "p2",
            "rules": [
                {"id": "human-refund", "effect": "require_approval",
                 "match": {"tool": "refund"}},
                {"id": "ok", "effect": "allow", "match": {}},
            ],
        },
    )["id"]
    grant = env._post(
        "/v1/control/grants",
        {
            "tenantId": tenant,
            "userId": user,
            "agentId": agent,
            "policyId": policy,
            "authorization": [{"upstream": "billing", "tools": ["*"]}],
            "budgetMaxUnits": 100,
        },
    )["id"]
    sdk = env.sdk(grant, agent_id=agent, private_jwk=keys.private_jwk)
    for i in range(8):
        sdk.call("billing", "charge", {"invoice": i})
    parked = sdk.call("billing", "refund", {"invoice": 0})
    assert isinstance(parked, PendingApproval)
    now = datetime.now(UTC).isoformat()
    for i, status in enumerate(("delivered", "delivered", "failed")):
        env.ctx.store.put_delivery(
            Delivery(
                id=f"dlv_busy_{i}", tenantId=tenant, channelId="chn_b",
                channelType="webhook", approvalId=parked.approval_id, event="parked",
                status=status,  # type: ignore[arg-type]
                nextAttemptAt=now, createdAt=now, updatedAt=now,
            )
        )
    return {"tenant": tenant, "agent": agent, "grant": grant}


def test_busier_tenant_never_leaks_into_quiet_tenant(env: Env) -> None:
    busy = _provision_busy_tenant(env)
    env.sdk().call("crm", "read_contact", {"id": "c1"})  # one call so A is non-empty

    a = env.dashboard()
    assert a["totals"] == {
        "calls": 1, "executed": 1, "denied": 0, "parked": 0, "errors": 0,
        "costUnits": 1, "activeAgents": 1,
    }
    assert a["topTools"] == [{"tool": "crm.read_contact", "calls": 1, "denied": 0}]
    assert all(not t["tool"].startswith("billing.") for t in a["topTools"])
    assert [b["grantId"] for b in a["budgets"]] == [env.grant]
    assert busy["grant"] not in {b["grantId"] for b in a["budgets"]}
    assert busy["agent"] not in {b["agentId"] for b in a["budgets"]}
    assert a["approvals"] == {"pending": 0, "oldestPendingAgeSeconds": None}
    assert a["operational"]["deliveries"] == {"pending": 0, "delivered": 0, "failed": 0}

    b = env.dashboard(tenant=busy["tenant"])
    assert b["totals"]["calls"] == 9
    assert b["totals"]["parked"] == 1
    assert b["totals"]["costUnits"] == 24
    assert b["approvals"]["pending"] == 1
    assert b["operational"]["deliveries"] == {"pending": 0, "delivered": 2, "failed": 1}


# --- adversarial: role gating with real operator keys -------------------------------------


def test_auditor_operator_key_reads_dashboard_but_disabled_key_cannot(env: Env) -> None:
    created = env._post("/v1/control/operators", {"name": "aud", "role": "auditor"})
    headers = {"x-toolgate-operator-key": created["key"]}

    ok = env.client.get(
        "/v1/control/dashboard", headers=headers, params={"tenantId": env.tenant}
    )
    assert ok.status_code == 200
    assert ok.json()["tenantId"] == env.tenant

    # auditor is read-only: an owner-level mutation with the same key is refused.
    mutate = env.client.post("/v1/control/tenants", headers=headers, json={"name": "X"})
    assert mutate.status_code == 403
    assert mutate.json()["error"]["code"] == "TG_DENIED"

    env._post(f"/v1/control/operators/{created['operator']['id']}/disable", {})
    revoked = env.client.get(
        "/v1/control/dashboard", headers=headers, params={"tenantId": env.tenant}
    )
    assert revoked.status_code == 401
    assert revoked.json()["error"]["code"] == "TG_TOKEN_INVALID"


# --- adversarial: malformed input ---------------------------------------------------------


def test_malformed_hours_is_400_envelope_not_500(env: Env) -> None:
    bad = env.client.get(
        "/v1/control/dashboard",
        headers=env.admin,
        params={"tenantId": env.tenant, "hours": "abc"},
    )
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == "TG_VALIDATION"

    fractional = env.client.get(
        "/v1/control/dashboard",
        headers=env.admin,
        params={"tenantId": env.tenant, "hours": "1.5"},
    )
    assert fractional.status_code == 400
    assert fractional.json()["error"]["code"] == "TG_VALIDATION"


def test_missing_tenant_id_is_400_envelope(env: Env) -> None:
    missing = env.client.get("/v1/control/dashboard", headers=env.admin)
    assert missing.status_code == 400
    body = missing.json()
    assert body["error"]["code"] == "TG_VALIDATION"
    assert any("tenantId" in issue for issue in body["error"]["details"]["issues"])


# --- adversarial: record/grant/approval robustness ----------------------------------------


def test_records_missing_latency_and_cost_do_not_break_totals(env: Env) -> None:
    now = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)
    _gate_record(env, now - timedelta(minutes=5), "executed", cost=None)
    _gate_record(env, now - timedelta(minutes=4), "error", cost=None)
    body = build_dashboard(env.ctx, env.tenant, 24, now=now)
    assert body["totals"]["calls"] == 2
    assert body["totals"]["executed"] == 1
    assert body["totals"]["errors"] == 1
    assert body["totals"]["costUnits"] == 0  # absent costUnits counts as 0, not a crash


def test_budget_exhausted_and_revoked_grants_still_listed(env: Env) -> None:
    tight = env.make_grant(budget=2)
    sdk = env.sdk(tight)
    sdk.call("crm", "read_contact", {"id": "1"})
    sdk.call("crm", "read_contact", {"id": "2"})  # spent == max: utilization exactly 1.0
    env._post(f"/v1/control/grants/{env.grant}/revoke", {})

    budgets = env.dashboard()["budgets"]
    by_id = {b["grantId"]: b for b in budgets}
    assert by_id[tight]["spentUnits"] == by_id[tight]["maxUnits"] == 2
    assert budgets[0]["grantId"] == tight  # utilization 1.0 sorts first
    assert by_id[env.grant]["status"] == "revoked"  # revoked grants stay visible


def test_expired_but_pending_approval_age_is_non_negative(env: Env) -> None:
    now = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)
    env.ctx.store.put_approval(
        ApprovalRequest(
            id="apr_stale", tenantId=env.tenant, callId=new_id("call"),
            grantId=env.grant, agentId=env.agent, userId=env.user,
            upstream="crm", tool="wire_money", args={"amount": 1},
            status="pending",
            requestedAt=(now - timedelta(hours=2)).isoformat(),
            expiresAt=(now - timedelta(hours=1)).isoformat(),  # expired yet still pending
        )
    )
    body = build_dashboard(env.ctx, env.tenant, 24, now=now)
    assert body["approvals"]["pending"] == 1
    assert body["approvals"]["oldestPendingAgeSeconds"] == 7200


def test_top_tools_truncated_to_ten_and_sorted(env: Env) -> None:
    now = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)
    for i in range(12):
        for _ in range(i + 1):
            _gate_record(env, now - timedelta(minutes=1), tool=f"t{i:02d}")
    top = build_dashboard(env.ctx, env.tenant, 24, now=now)["topTools"]
    assert len(top) == 10
    assert top[0] == {"tool": "crm.t11", "calls": 12, "denied": 0}
    assert [t["calls"] for t in top] == sorted((t["calls"] for t in top), reverse=True)
    assert {"crm.t00", "crm.t01"}.isdisjoint({t["tool"] for t in top})


# --- adversarial: determinism and read-only guarantees ------------------------------------


def test_identical_payloads_and_zero_state_mutation(env: Env) -> None:
    _seed_activity(env)
    now = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)
    tables = [
        r[0]
        for r in env.ctx.store.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    ]

    def row_counts() -> dict[str, int]:
        return {
            t: env.ctx.store.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in tables
        }

    before_counts = row_counts()
    before_last = env.ctx.store.last_audit()
    first = build_dashboard(env.ctx, env.tenant, 24, now=now)
    second = build_dashboard(env.ctx, env.tenant, 24, now=now)
    assert first == second  # fully deterministic under an injected now
    assert row_counts() == before_counts  # no table in the store changed at all
    assert env.ctx.store.last_audit() == before_last  # chain head untouched


def test_error_paths_append_no_audit_records(env: Env) -> None:
    before = len(env.ctx.store.list_audit())
    env.client.get(
        "/v1/control/dashboard", headers=env.admin, params={"tenantId": "tnt_missing"}
    )
    env.client.get(
        "/v1/control/dashboard",
        headers=env.admin,
        params={"tenantId": env.tenant, "hours": "abc"},
    )
    env.client.get("/v1/control/dashboard", params={"tenantId": env.tenant})  # unauthenticated
    chain = env.ctx.store.list_audit()
    assert len(chain) == before
    assert all("dashboard" not in r.action.tool for r in chain)
