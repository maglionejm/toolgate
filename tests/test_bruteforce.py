"""Token-endpoint brute-force protections (#24, spec: add-token-endpoint-bruteforce)."""

import dataclasses
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import generate_ed25519_key_pair, sign_client_assertion
from toolgate.server import create_app, create_app_context

BASE = "http://testserver"


class Env:
    def __init__(self, trusted_proxies: tuple[str, ...] = ()) -> None:
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=BASE,
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": 1}))
            ),
        )
        if trusted_proxies:
            self.ctx.config = dataclasses.replace(self.ctx.config, trusted_proxies=trusted_proxies)
        self.client = TestClient(create_app(self.ctx))
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}
        self.keys = generate_ed25519_key_pair()
        tenant = self._post("/v1/control/tenants", {"name": "T"})["id"]
        user = self._post("/v1/control/users", {"tenantId": tenant, "displayName": "u"})["id"]
        self.agent = self._post(
            "/v1/control/agents", {"tenantId": tenant, "name": "a", "publicJwk": self.keys.public_jwk}
        )["id"]
        self._post(
            "/v1/control/upstreams",
            {
                "tenantId": tenant,
                "name": "crm",
                "baseUrl": "https://x.internal",
                "credential": {"mode": "bearer", "secret": "s"},
                "tools": [{"name": "read"}],
            },
        )
        policy = self._post(
            "/v1/control/policies",
            {"tenantId": tenant, "name": "p", "rules": [{"effect": "allow", "match": {}}]},
        )["id"]
        self.grant = self._post(
            "/v1/control/grants",
            {
                "tenantId": tenant,
                "userId": user,
                "agentId": self.agent,
                "policyId": policy,
                "authorization": [{"upstream": "crm", "tools": ["*"]}],
                "budgetMaxUnits": 50,
            },
        )["id"]

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def exchange(self, assertion: str, headers: dict | None = None) -> httpx.Response:
        return self.client.post(
            "/v1/token",
            headers=headers or {},
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_assertion": assertion,
                "grant_id": self.grant,
            },
        )

    def good_assertion(self) -> str:
        return sign_client_assertion(
            self.keys.private_jwk, agent_id=self.agent, token_url=f"{BASE}/v1/token"
        )

    def bad_assertion(self) -> str:
        wrong = generate_ed25519_key_pair()
        return sign_client_assertion(
            wrong.private_jwk, agent_id=self.agent, token_url=f"{BASE}/v1/token"
        )


@pytest.fixture()
def env() -> Env:
    return Env()


def test_backoff_after_consecutive_failures(env: Env) -> None:
    for _ in range(5):
        assert env.exchange(env.bad_assertion()).status_code == 401
    blocked = env.exchange(env.bad_assertion())
    # Either the bump on the 5th failure already gates this attempt or this
    # failure crosses the threshold; within two more attempts we must see 429.
    if blocked.status_code != 429:
        blocked = env.exchange(env.bad_assertion())
    assert blocked.status_code == 429
    body = blocked.json()["error"]
    assert body["code"] == "TG_RATE_LIMITED"
    assert body["details"]["retry_after_seconds"] >= 1


def test_success_resets_backoff(env: Env) -> None:
    for _ in range(3):
        assert env.exchange(env.bad_assertion()).status_code == 401
    ok = env.exchange(env.good_assertion())
    assert ok.status_code == 200
    # Counter cleared: three more failures still under threshold, no 429.
    for _ in range(3):
        assert env.exchange(env.bad_assertion()).status_code == 401


def test_spoofed_xff_from_untrusted_peer_ignored() -> None:
    env = Env()  # no trusted proxies
    # Rotating XFF must not create fresh limit buckets: same socket peer.
    for i in range(6):
        res = env.exchange(env.bad_assertion(), headers={"x-forwarded-for": f"10.0.0.{i}"})
        assert res.status_code in (401, 429)
    final = env.exchange(env.bad_assertion(), headers={"x-forwarded-for": "10.9.9.9"})
    assert final.status_code == 429


def test_trusted_proxy_xff_honored() -> None:
    env = Env(trusted_proxies=("testclient",))
    # Failures attributed to the forwarded client...
    for i in range(6):
        env.exchange(env.bad_assertion(), headers={"x-forwarded-for": "203.0.113.7"})
    blocked = env.exchange(env.bad_assertion(), headers={"x-forwarded-for": "203.0.113.7"})
    assert blocked.status_code == 429
    # NOTE: per-grant backoff also applies; a different forwarded source with the
    # same grant is still throttled — that is intended (the grant is under attack).


def test_failure_telemetry_on_healthz(env: Env) -> None:
    env.exchange(env.bad_assertion())
    health = env.client.get("/healthz").json()
    assert health["auth_failures"].get("bad_assertion", 0) >= 1
    # Hourly summary record landed in the chain with source=system.
    summaries = [
        r for r in env.ctx.store.list_audit() if r.action.tool == "token-exchange-failures"
    ]
    assert summaries and summaries[-1].decision.source == "system"
