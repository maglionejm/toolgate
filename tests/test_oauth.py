"""Upstream OAuth brokering (#11, spec: add-upstream-oauth-brokering).

A fake provider lives behind the gate's mock transport: it exchanges codes,
refreshes tokens, and the fake upstream records which bearer token arrived —
so per-user injection, transparent refresh, and instant revocation are all
asserted end to end.
"""

import json
import time
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import generate_ed25519_key_pair
from toolgate.sdk import ToolgateCallError, ToolgateClient
from toolgate.server import create_app, create_app_context

BASE = "http://testserver"
IDP = "https://idp.example"
CRM = "https://crm.internal"


class FakeProvider:
    """OAuth provider + protected upstream in one transport."""

    def __init__(self) -> None:
        self.token_counter = 0
        self.refresh_ok = True
        self.upstream_calls: list[str] = []  # bearer tokens seen by the upstream
        self.codes: dict[str, str] = {"good-code-sam": "sam", "good-code-ana": "ana"}

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(f"{IDP}/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            if form.get("client_secret") != "shh-client-secret":
                return httpx.Response(401, json={"error": "invalid_client"})
            if form.get("grant_type") == "authorization_code":
                who = self.codes.get(form.get("code", ""))
                if who is None or not form.get("code_verifier"):
                    return httpx.Response(400, json={"error": "invalid_grant"})
                self.token_counter += 1
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"at-{who}-{self.token_counter}",
                        "refresh_token": f"rt-{who}",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                    },
                )
            if form.get("grant_type") == "refresh_token":
                if not self.refresh_ok or not form.get("refresh_token", "").startswith("rt-"):
                    return httpx.Response(400, json={"error": "invalid_grant"})
                who = form["refresh_token"].removeprefix("rt-")
                self.token_counter += 1
                return httpx.Response(
                    200,
                    json={"access_token": f"at-{who}-{self.token_counter}", "expires_in": 3600},
                )
            return httpx.Response(400, json={"error": "unsupported_grant_type"})
        if url.startswith(CRM):
            self.upstream_calls.append(request.headers.get("authorization", ""))
            return httpx.Response(200, json={"ok": 1})
        return httpx.Response(404, json={"error": f"unrouted {url}"})


class Env:
    def __init__(self) -> None:
        self.provider = FakeProvider()
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=BASE,
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(self.provider.handler)
            ),
        )
        self.client = TestClient(create_app(self.ctx))
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}

        self.tenant = self._post("/v1/control/tenants", {"name": "Acme"})["id"]
        self.sam = self._post(
            "/v1/control/users", {"tenantId": self.tenant, "displayName": "Sam"}
        )["id"]
        self.ana = self._post(
            "/v1/control/users", {"tenantId": self.tenant, "displayName": "Ana"}
        )["id"]
        self.app_id = self._post(
            "/v1/control/provider-apps",
            {
                "tenantId": self.tenant,
                "name": "fake-idp",
                "clientId": "client-1",
                "clientSecret": "shh-client-secret",
                "authorizeUrl": f"{IDP}/authorize",
                "tokenUrl": f"{IDP}/token",
                "scopes": ["crm.read", "crm.write"],
            },
        )["id"]
        self._post(
            "/v1/control/upstreams",
            {
                "tenantId": self.tenant,
                "name": "crm",
                "baseUrl": CRM,
                "credential": {"mode": "oauth_user", "providerAppId": self.app_id},
                "tools": [{"name": "read_contact", "costUnits": 1}],
            },
        )
        policy = self._post(
            "/v1/control/policies",
            {"tenantId": self.tenant, "name": "p",
             "rules": [{"id": "ok", "effect": "allow", "match": {}}]},
        )["id"]
        self.policy = policy

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def grant_for(self, user_id: str) -> tuple[str, Any]:
        keys = generate_ed25519_key_pair()
        agent = self._post(
            "/v1/control/agents",
            {"tenantId": self.tenant, "name": f"a-{user_id}", "publicJwk": keys.public_jwk},
        )["id"]
        grant = self._post(
            "/v1/control/grants",
            {
                "tenantId": self.tenant,
                "userId": user_id,
                "agentId": agent,
                "policyId": self.policy,
                "authorization": [{"upstream": "crm", "tools": ["*"]}],
                "budgetMaxUnits": 50,
            },
        )["id"]
        return grant, (agent, keys)

    def sdk(self, grant: str, agent_and_keys: tuple) -> ToolgateClient:
        outer = self
        agent, keys = agent_and_keys

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

    def connect(self, user_id: str, code: str) -> dict[str, Any]:
        """Drive the full authorize flow: start -> simulate consent -> callback."""
        started = self._post(
            "/v1/control/connections/start",
            {"tenantId": self.tenant, "userId": user_id, "providerAppId": self.app_id},
        )
        query = dict(parse_qsl(urlsplit(started["authorizeUrl"]).query))
        assert query["code_challenge_method"] == "S256" and query["code_challenge"]
        assert query["redirect_uri"] == f"{BASE}/v1/connections/callback"
        res = self.client.get(
            f"/v1/connections/callback?state={query['state']}&code={code}"
        )
        return {"status": res.status_code, "text": res.text, "state": query["state"]}


@pytest.fixture()
def env() -> Env:
    return Env()


# --- provider apps ---------------------------------------------------------------------


def test_client_secret_sealed_and_never_returned(env: Env) -> None:
    listed = env.client.get(
        f"/v1/control/provider-apps?tenantId={env.tenant}", headers=env.admin
    ).json()
    assert "shh-client-secret" not in json.dumps(listed)
    assert listed[0]["clientSecretRef"].startswith("sec_")


# --- connect flow ----------------------------------------------------------------------


def test_connect_flow_creates_bound_connection(env: Env) -> None:
    out = env.connect(env.sam, "good-code-sam")
    assert out["status"] == 200 and "Connected" in out["text"]

    connections = env.client.get(
        f"/v1/control/connections?tenantId={env.tenant}", headers=env.admin
    ).json()
    assert len(connections) == 1
    c = connections[0]
    assert c["userId"] == env.sam and c["providerAppId"] == env.app_id
    assert c["status"] == "active"
    # Token refs never appear on the read surface.
    assert "accessTokenRef" not in c and "refreshTokenRef" not in c

    # State is single-use: replaying the callback decides nothing new.
    replay = env.client.get(
        f"/v1/connections/callback?state={out['state']}&code=good-code-sam"
    )
    assert replay.status_code == 400
    assert "already-used" in replay.text or "unknown" in replay.text


# --- oauth_user injection ---------------------------------------------------------------


def test_gate_injects_user_token(env: Env) -> None:
    env.connect(env.sam, "good-code-sam")
    grant, agent_keys = env.grant_for(env.sam)
    done = env.sdk(grant, agent_keys).call("crm", "read_contact", {"contactId": "c1"})
    assert done.status == "executed"
    assert env.provider.upstream_calls[-1].startswith("Bearer at-sam-")


def test_expired_token_refreshes_transparently(env: Env) -> None:
    env.connect(env.sam, "good-code-sam")
    grant, agent_keys = env.grant_for(env.sam)
    sdk = env.sdk(grant, agent_keys)
    assert sdk.call("crm", "read_contact", {"contactId": "c1"}).status == "executed"
    first_token = env.provider.upstream_calls[-1]

    # Force expiry: the next call must refresh server-side and proceed.
    connection = env.ctx.store.find_connection(env.tenant, env.app_id, env.sam)
    assert connection is not None
    connection.expiresAt = "2000-01-01T00:00:00+00:00"
    env.ctx.store.put_connection(connection)

    assert sdk.call("crm", "read_contact", {"contactId": "c2"}).status == "executed"
    second_token = env.provider.upstream_calls[-1]
    assert second_token != first_token and second_token.startswith("Bearer at-sam-")


def test_refresh_failure_is_typed_and_audited(env: Env) -> None:
    env.connect(env.sam, "good-code-sam")
    grant, agent_keys = env.grant_for(env.sam)
    connection = env.ctx.store.find_connection(env.tenant, env.app_id, env.sam)
    connection.expiresAt = "2000-01-01T00:00:00+00:00"
    env.ctx.store.put_connection(connection)
    env.provider.refresh_ok = False

    with pytest.raises(ToolgateCallError) as err:
        env.sdk(grant, agent_keys).call("crm", "read_contact", {"contactId": "c3"})
    assert err.value.code == "TG_CONNECTION_FAILED"
    records = env.ctx.store.list_audit(env.tenant)
    assert records[-1].result.status == "error"


def test_missing_connection_fails_before_upstream(env: Env) -> None:
    grant, agent_keys = env.grant_for(env.ana)  # Ana never connected
    with pytest.raises(ToolgateCallError) as err:
        env.sdk(grant, agent_keys).call("crm", "read_contact", {"contactId": "c4"})
    assert err.value.code == "TG_CONNECTION_REQUIRED"
    assert "connections/start" in err.value.message
    assert env.provider.upstream_calls == []  # the upstream was never invoked


def test_cross_user_isolation(env: Env) -> None:
    env.connect(env.sam, "good-code-sam")
    env.connect(env.ana, "good-code-ana")
    sam_grant, sam_ak = env.grant_for(env.sam)
    ana_grant, ana_ak = env.grant_for(env.ana)

    env.sdk(sam_grant, sam_ak).call("crm", "read_contact", {"contactId": "c5"})
    env.sdk(ana_grant, ana_ak).call("crm", "read_contact", {"contactId": "c6"})

    sam_token, ana_token = env.provider.upstream_calls[-2:]
    assert sam_token.startswith("Bearer at-sam-")
    assert ana_token.startswith("Bearer at-ana-")


# --- revocation --------------------------------------------------------------------------


def test_revoke_is_instant_and_deletes_tokens(env: Env) -> None:
    env.connect(env.sam, "good-code-sam")
    grant, agent_keys = env.grant_for(env.sam)
    sdk = env.sdk(grant, agent_keys)
    assert sdk.call("crm", "read_contact", {"contactId": "c7"}).status == "executed"

    connection = env.ctx.store.find_connection(env.tenant, env.app_id, env.sam)
    res = env.client.post(
        f"/v1/control/connections/{connection.id}/revoke", headers=env.admin, json={}
    )
    assert res.status_code == 200 and res.json()["tokensDeleted"] is True

    # Sealed tokens are gone, not just flagged.
    assert env.ctx.store.get_secret(connection.accessTokenRef) is None
    if connection.refreshTokenRef:
        assert env.ctx.store.get_secret(connection.refreshTokenRef) is None

    calls_before = len(env.provider.upstream_calls)
    with pytest.raises(ToolgateCallError) as err:
        sdk.call("crm", "read_contact", {"contactId": "c8"})
    assert err.value.code == "TG_CONNECTION_REQUIRED"
    assert len(env.provider.upstream_calls) == calls_before

    # Lifecycle events all landed in the audit chain.
    tools = [r.action.tool for r in env.ctx.store.list_audit(env.tenant)]
    assert "connections.start" in tools
    assert "connections.connect" in tools
    assert "connections.revoke" in tools


def test_reconnect_replaces_connection(env: Env) -> None:
    env.connect(env.sam, "good-code-sam")
    first = env.ctx.store.find_connection(env.tenant, env.app_id, env.sam)
    time.sleep(0.01)
    env.connect(env.sam, "good-code-sam")
    connections = env.ctx.store.list_connections(env.tenant, env.sam)
    assert len(connections) == 1  # deterministic id: one connection per user+app
    assert connections[0].createdAt == first.createdAt
    assert connections[0].updatedAt >= first.updatedAt
