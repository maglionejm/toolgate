"""Postgres store + multi-instance correctness (#16, spec: add-postgres-scale-out).

Runs only when TOOLGATE_TEST_PG_DSN points at a reachable Postgres (the CI
`postgres` job provides one; locally: docker run -e POSTGRES_PASSWORD=tg -e
POSTGRES_USER=tg -e POSTGRES_DB=toolgate -p 5433:5432 postgres:16 and export
TOOLGATE_TEST_PG_DSN=postgresql://tg:tg@localhost:5433/toolgate).

"Two instances" here means two full AppContexts (separate key caches, separate
in-memory state) sharing one database — exactly the deployment shape behind a
load balancer.
"""

import json
import os
import threading
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import generate_ed25519_key_pair, sign_client_assertion, sign_pop_proof
from toolgate.sdk import PendingApproval, ToolgateCallError, ToolgateClient
from toolgate.server import create_app, create_app_context

DSN = os.environ.get("TOOLGATE_TEST_PG_DSN", "")
BASE = "http://testserver"

pytestmark = pytest.mark.skipif(not DSN, reason="TOOLGATE_TEST_PG_DSN not set")

_TABLES = (
    "settings", "entities", "grant_budgets", "used_jtis", "secrets", "audit",
    "checkpoints", "txn_taint", "auth_failures", "deliveries", "link_tokens",
    "oauth_states", "rate_windows",
)


@pytest.fixture(autouse=True)
def _clean_database() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(DSN, autocommit=True) as conn:
        for table in _TABLES:
            conn.execute(f"DROP TABLE IF EXISTS {table} CASCADE")  # noqa: S608


def _mock_http() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": 1}))
    )


class Instance:
    """One server instance on the shared database."""

    def __init__(self) -> None:
        self.ctx = create_app_context(db_path=DSN, public_url=BASE, http_client=_mock_http())
        self.app = create_app(self.ctx)
        self.client = TestClient(self.app)
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def sdk(self, agent: str, keys: Any, grant: str) -> ToolgateClient:
        outer = self

        class Bridge(httpx.Client):
            def request(inner, method: str, url: Any, **kw: Any) -> httpx.Response:  # noqa: N805
                return outer.client.request(method, str(url), **kw)

        return ToolgateClient(
            base_url=BASE,
            agent_id=agent,
            agent_private_jwk=keys.private_jwk,
            grant_id=grant,
            http_client=Bridge(),
        )


def _seed(instance: Instance, budget: int = 20) -> tuple[str, Any, str]:
    """Tenant + agent + upstream + policy + grant; returns (agent_id, keys, grant_id)."""
    keys = generate_ed25519_key_pair()
    tenant = instance.post("/v1/control/tenants", {"name": "Acme"})["id"]
    user = instance.post("/v1/control/users", {"tenantId": tenant, "displayName": "Sam"})["id"]
    agent = instance.post(
        "/v1/control/agents", {"tenantId": tenant, "name": "a", "publicJwk": keys.public_jwk}
    )["id"]
    instance.post(
        "/v1/control/upstreams",
        {
            "tenantId": tenant,
            "name": "crm",
            "baseUrl": "https://crm.internal",
            "credential": {"mode": "bearer", "secret": "k"},
            "tools": [
                {"name": "read", "costUnits": 1},
                {"name": "wire", "sideEffecting": True, "costUnits": 1},
            ],
        },
    )
    policy = instance.post(
        "/v1/control/policies",
        {
            "tenantId": tenant,
            "name": "p",
            "rules": [
                {"id": "human-wire", "effect": "require_approval", "match": {"tool": "wire"}},
                {"id": "ok", "effect": "allow", "match": {}},
            ],
        },
    )["id"]
    grant = instance.post(
        "/v1/control/grants",
        {
            "tenantId": tenant,
            "userId": user,
            "agentId": agent,
            "policyId": policy,
            "authorization": [{"upstream": "crm", "tools": ["*"]}],
            "budgetMaxUnits": budget,
        },
    )["id"]
    return agent, keys, grant


# --- backend parity ---------------------------------------------------------------------


def test_full_flow_unchanged_semantics_on_postgres() -> None:
    a = Instance()
    agent, keys, grant = _seed(a)
    sdk = a.sdk(agent, keys, grant)

    done = sdk.call("crm", "read", {"contactId": "c1"})
    assert done.status == "executed"

    parked = sdk.call("crm", "wire", {"amount": 5})
    assert isinstance(parked, PendingApproval)
    a.post(f"/v1/control/approvals/{parked.approval_id}/decide", {"decision": "approve"})
    executed = sdk.execute_approval(parked.approval_id)
    assert executed.status == "executed"

    verify = a.client.get("/v1/control/audit/verify", headers=a.admin).json()
    assert verify["valid"] is True and verify["length"] >= 3


def test_second_instance_shares_state() -> None:
    a = Instance()
    agent, keys, grant = _seed(a)
    b = Instance()  # boots against the same database: same keys, same admin key
    assert b.ctx.config.admin_key == a.ctx.config.admin_key
    assert b.ctx.gate_keys.kid == a.ctx.gate_keys.kid

    # Call via B against state seeded via A.
    done = b.sdk(agent, keys, grant).call("crm", "read", {"contactId": "c2"})
    assert done.status == "executed"

    # Both instances appended to one chain; it verifies from either side.
    assert a.client.get("/v1/control/audit/verify", headers=a.admin).json()["valid"]
    assert b.client.get("/v1/control/audit/verify", headers=b.admin).json()["valid"]


# --- exactly-once across instances ------------------------------------------------------


def test_cross_instance_budget_race_charges_exactly_once() -> None:
    a = Instance()
    agent, keys, grant = _seed(a, budget=1)
    b = Instance()
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def call(instance: Instance) -> None:
        sdk = instance.sdk(agent, keys, grant)
        barrier.wait()
        try:
            sdk.call("crm", "read", {"contactId": "c-race"})
            outcomes.append("executed")
        except ToolgateCallError as err:
            outcomes.append(err.code)

    threads = [threading.Thread(target=call, args=(i,)) for i in (a, b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(outcomes) == ["TG_BUDGET_EXCEEDED", "executed"]
    final = a.ctx.store.get_grant(grant)
    assert final is not None and final.budget.spentUnits == 1


def test_cross_instance_proof_replay_rejected() -> None:
    a = Instance()
    agent, keys, grant = _seed(a)
    b = Instance()

    assertion = sign_client_assertion(
        keys.private_jwk, agent_id=agent, token_url=f"{BASE}/v1/token"
    )
    token = a.client.post(
        "/v1/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_assertion": assertion,
            "grant_id": grant,
        },
    ).json()["access_token"]

    body = json.dumps({"tool": "read", "args": {"contactId": "c3"}}).encode()
    proof = sign_pop_proof(
        keys.private_jwk,
        htm="POST",
        htu=f"{BASE}/v1/gate/call/crm",
        access_token=token,
        body=body,
    )
    headers = {
        "authorization": f"Bearer {token}",
        "x-toolgate-proof": proof,
        "content-type": "application/json",
    }
    first = a.client.post("/v1/gate/call/crm", headers=headers, content=body)
    assert first.status_code == 200, first.text

    # The identical proof replayed against the OTHER instance must die: the
    # jti was consumed in shared state, not process memory.
    replay = b.client.post("/v1/gate/call/crm", headers=headers, content=body)
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "TG_PROOF_INVALID"


def test_revoke_on_a_refuses_on_b() -> None:
    a = Instance()
    agent, keys, grant = _seed(a)
    b = Instance()
    sdk_b = b.sdk(agent, keys, grant)
    assert sdk_b.call("crm", "read", {"contactId": "c4"}).status == "executed"

    a.post(f"/v1/control/grants/{grant}/revoke", {})
    with pytest.raises(ToolgateCallError) as err:
        sdk_b.call("crm", "read", {"contactId": "c5"})
    assert err.value.code == "TG_REVOKED"


def test_shared_rate_limit_across_instances() -> None:
    from toolgate.server.ratelimit import DbRateLimiter

    a = Instance()
    b = Instance()
    limiter_a = DbRateLimiter(a.ctx.store, max_events=5, window_seconds=60.0)
    limiter_b = DbRateLimiter(b.ctx.store, max_events=5, window_seconds=60.0)

    allowed = sum(
        1
        for i in range(10)
        if (limiter_a if i % 2 == 0 else limiter_b).allow("grant:shared")
    )
    # Split traffic cannot exceed the combined ceiling.
    assert allowed == 5
    # Other keys are unaffected.
    assert limiter_b.allow("grant:other")


# --- migration --------------------------------------------------------------------------


def test_sqlite_to_postgres_migration_preserves_chain(tmp_path: Any) -> None:
    from toolgate.server.store_pg import migrate_sqlite_to_postgres

    sqlite_path = str(tmp_path / "source.db")
    src = Instance.__new__(Instance)  # build a SQLite instance by hand
    src.ctx = create_app_context(db_path=sqlite_path, public_url=BASE, http_client=_mock_http())
    src.app = create_app(src.ctx)
    src.client = TestClient(src.app)
    src.admin = {"x-toolgate-admin-key": src.ctx.config.admin_key}
    agent, keys, grant = _seed(src)
    assert src.sdk(agent, keys, grant).call("crm", "read", {"contactId": "m1"}).status == "executed"
    src.ctx.audit.checkpoint()
    source_verify = src.client.get("/v1/control/audit/verify", headers=src.admin).json()

    result = migrate_sqlite_to_postgres(sqlite_path, DSN)
    assert result["valid"] is True
    assert result["length"] == source_verify["length"]

    # A fresh instance boots on the migrated database and verifies the chain.
    migrated = Instance()
    verify = migrated.client.get("/v1/control/audit/verify", headers=migrated.admin).json()
    assert verify["valid"] is True and verify["length"] == source_verify["length"]
    # Sealed secrets survived verbatim (vault opens them with the migrated key).
    refs = migrated.ctx.store.list_secret_refs()
    assert refs and migrated.ctx.vault.open(migrated.ctx.store.get_secret(refs[0])) == "k"


# --- store contract ---------------------------------------------------------------------


def test_pg_store_contract_atomics() -> None:
    instance = Instance()
    store = instance.ctx.store

    # One-time jtis: second consume is refused.
    assert store.consume_jti("jti-1", "proof", 60) is True
    assert store.consume_jti("jti-1", "proof", 60) is False

    # Taint with expiry.
    store.mark_taint(["txn-1", "grant:g1"])
    assert store.is_tainted(["txn-1"]) and store.is_tainted(["grant:g1"])
    assert not store.is_tainted(["txn-other"])

    # Auth failure backoff counters.
    for _ in range(5):
        store.auth_failure_bump("src:1.2.3.4")
    assert store.auth_backoff_remaining("src:1.2.3.4") >= 1
    store.auth_failures_clear("src:1.2.3.4")
    assert store.auth_backoff_remaining("src:1.2.3.4") == 0

    # Link tokens: single consume.
    store.put_link_token("hash-1", {"approvalId": "apr_x"})
    assert store.consume_link_token("hash-1")[0] == "ok"
    assert store.consume_link_token("hash-1")[0] == "used"
    assert store.consume_link_token("hash-missing")[0] == "unknown"
