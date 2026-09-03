"""Regression tests for the round-1/round-2 security fixes.

Each test reproduces an exploit (or its precondition) and asserts it is now
closed. Grouped by finding id.
"""

import asyncio
import base64
import hashlib
import json
import os
import stat
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from jwcrypto import jwk, jws, jwt

from toolgate.core import (
    ErrorCodes,
    ToolgateError,
    generate_ed25519_key_pair,
    mint_capability_token,
    sign_client_assertion,
    sign_pop_proof,
    validate_public_ed25519_jwk,
    verify_client_assertion,
    verify_pop_proof,
)
from toolgate.core.policy import (
    ToolCallContext,
    evaluate_policy,
    is_within_authorization,
)
from toolgate.core.types import (
    AuthorizationDetail,
    Policy,
    PolicyRule,
)
from toolgate.server import create_app, create_app_context
from toolgate.server.control import _validate_upstream_base_url
from toolgate.server.store import Store

PUBLIC_URL = "http://testserver"


def _fresh_env():
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append({"url": str(request.url)})
        return httpx.Response(200, json={"ok": True})

    ctx = create_app_context(
        db_path=":memory:",
        public_url=PUBLIC_URL,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    client = TestClient(create_app(ctx))
    admin = {"x-toolgate-admin-key": ctx.config.admin_key}

    def post(path, body):
        r = client.post(path, json=body, headers=admin)
        assert r.status_code < 300, f"{path} -> {r.status_code}: {r.text}"
        return r.json()

    tenant = post("/v1/control/tenants", {"name": "Acme"})["id"]
    user = post("/v1/control/users", {"tenantId": tenant, "displayName": "Sam"})["id"]
    return ctx, client, admin, post, tenant, user, calls


def _authed_env():
    """A fully wired env plus a helper to make a signed gate call to `email`."""
    ctx, client, admin, post, tenant, user, calls = _fresh_env()
    agent_keys = generate_ed25519_key_pair()
    agent = post(
        "/v1/control/agents",
        {"tenantId": tenant, "name": "a", "publicJwk": agent_keys.public_jwk},
    )["id"]
    post(
        "/v1/control/upstreams",
        {
            "tenantId": tenant,
            "name": "email",
            "baseUrl": "https://mail.internal",
            "credential": {"mode": "header", "headerName": "X-Api-Key", "secret": "k"},
            "tools": [{"name": "send_email", "costUnits": 1}],
        },
    )
    policy = post(
        "/v1/control/policies",
        {
            "tenantId": tenant,
            "name": "p",
            "rules": [{"id": "allow", "effect": "allow", "match": {"upstream": "email"}}],
        },
    )["id"]
    grant = post(
        "/v1/control/grants",
        {
            "tenantId": tenant,
            "userId": user,
            "agentId": agent,
            "policyId": policy,
            "authorization": [{"upstream": "email", "tools": ["send_email"]}],
            "budgetMaxUnits": 100,
        },
    )["id"]
    assertion = sign_client_assertion(
        agent_keys.private_jwk, agent_id=agent, token_url=f"{ctx.config.issuer}/v1/token"
    )
    token = client.post(
        "/v1/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_assertion": assertion,
            "grant_id": grant,
        },
    ).json()["access_token"]

    path = "/v1/gate/call/email"

    def _headers():
        proof = sign_pop_proof(
            agent_keys.private_jwk, htm="POST", htu=f"{PUBLIC_URL}{path}", access_token=token
        )
        return {"authorization": f"Bearer {token}", "x-toolgate-proof": proof}

    def call(args: dict):
        return client.post(path, headers=_headers(), json={"tool": "send_email", "args": args})

    def raw_call(body: str):
        headers = {**_headers(), "content-type": "application/json"}
        return client.post(path, headers=headers, content=body)

    return ctx, call, raw_call


# ---------------------------------------------------------------------------
# C1 — agent key must be a public Ed25519 key
# ---------------------------------------------------------------------------


def test_c1_create_agent_rejects_symmetric_oct_key():
    ctx, client, admin, post, tenant, _user, _calls = _fresh_env()
    oct_pub = json.loads(jwk.JWK.generate(kty="oct", size=256).export())
    r = client.post(
        "/v1/control/agents",
        json={"tenantId": tenant, "name": "evil", "publicJwk": oct_pub},
        headers=admin,
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == ErrorCodes.VALIDATION


def test_c1_create_agent_rejects_private_key():
    ctx, client, admin, post, tenant, _user, _calls = _fresh_env()
    priv = generate_ed25519_key_pair().private_jwk  # contains "d"
    r = client.post(
        "/v1/control/agents",
        json={"tenantId": tenant, "name": "leaky", "publicJwk": priv},
        headers=admin,
    )
    assert r.status_code == 400


def test_c1_validate_helper_accepts_real_public_key_only():
    validate_public_ed25519_jwk(generate_ed25519_key_pair().public_jwk)  # no raise
    for bad in (
        json.loads(jwk.JWK.generate(kty="oct", size=256).export()),
        generate_ed25519_key_pair().private_jwk,
        {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
        {"kty": "OKP", "crv": "X25519", "x": "a"},
    ):
        with pytest.raises(ValueError):
            validate_public_ed25519_jwk(bad)


def test_c1_pop_proof_rejects_symmetric_key_forgery():
    # A forged proof embedding an oct key and signed HS256 must be rejected even
    # though its thumbprint would match a (hypothetically) registered oct key.
    oct_key = jwk.JWK.generate(kty="oct", size=256)
    oct_pub = json.loads(oct_key.export())
    token = "fake-access-token"
    ath = base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()
    proof = jws.JWS(
        json.dumps(
            {
                "htm": "POST",
                "htu": f"{PUBLIC_URL}/x",
                "ath": ath,
                "iat": int(time.time()),
                "jti": "j",
            }
        ).encode()
    )
    proof.add_signature(
        oct_key,
        alg="HS256",
        protected=json.dumps({"alg": "HS256", "typ": "tg-pop+jwt", "jwk": oct_pub}),
    )
    with pytest.raises(ToolgateError) as err:
        verify_pop_proof(
            proof.serialize(compact=True),
            expected_jkt=oct_key.thumbprint(),
            htm="POST",
            htu=f"{PUBLIC_URL}/x",
            access_token=token,
        )
    assert err.value.code == ErrorCodes.PROOF_INVALID


# ---------------------------------------------------------------------------
# M9 / alg pin — client assertion
# ---------------------------------------------------------------------------


def test_m9_client_assertion_rejects_array_audience():
    kp = generate_ed25519_key_pair()
    key = jwk.JWK(**kp.private_jwk)
    now = int(time.time())
    t = jwt.JWT(
        header={"alg": "EdDSA", "typ": "tg-client+jwt"},
        claims={
            "iss": "agt_1",
            "sub": "agt_1",
            "aud": ["http://evil/v1/token", "http://good/v1/token"],
            "iat": now,
            "exp": now + 60,
            "jti": "j1",
        },
    )
    t.make_signed_token(key)
    with pytest.raises(ToolgateError):
        verify_client_assertion(kp.public_jwk, t.serialize(), expected_audience="http://good/v1/token")


# ---------------------------------------------------------------------------
# H2 — anchored approval regex closes the subdomain bypass
# ---------------------------------------------------------------------------


def _approval_policy() -> Policy:
    return Policy(
        id="pol_1",
        tenantId="t",
        name="default",
        createdAt="now",
        rules=[
            PolicyRule(
                id="approve-external",
                effect="require_approval",
                match={
                    "upstream": "email",
                    "tool": "send_email",
                    "where": [{"path": "to", "op": "matches", "value": "@(?!acme\\.com$)"}],
                },
            ),
            PolicyRule(
                id="allow-email",
                effect="allow",
                match={"upstream": "email", "tool": "send_email"},
            ),
        ],
    )


@pytest.mark.parametrize(
    "recipient,expected",
    [
        ("sam@acme.com", "allow"),
        ("cfo@globex.com", "require_approval"),
        ("cfo@acme.com.evil.com", "require_approval"),
        ("x@acme.com.attacker.tld", "require_approval"),
    ],
)
def test_h2_anchored_regex_closes_subdomain_bypass(recipient, expected):
    d = evaluate_policy(
        _approval_policy(),
        ToolCallContext(upstream="email", tool="send_email", args={"to": recipient}, cost_units=1),
    )
    assert d.effect == expected


# ---------------------------------------------------------------------------
# M1 — matches is fail-closed against runaway / oversized input
# ---------------------------------------------------------------------------


def test_m1_oversized_match_input_fails_closed():
    policy = Policy(
        id="p",
        tenantId="t",
        name="n",
        createdAt="x",
        rules=[
            PolicyRule(
                id="r",
                effect="allow",
                match={
                    "tool": "send_email",
                    "where": [{"path": "to", "op": "matches", "value": "(a+)+$"}],
                },
            )
        ],
    )
    # An input beyond the match-length cap must not be evaluated; the decision
    # fails closed to deny instead of hanging.
    d = evaluate_policy(
        policy,
        ToolCallContext(
            upstream="email", tool="send_email", args={"to": "a" * 10000}, cost_units=1
        ),
    )
    assert d.effect == "deny"
    assert d.source == "constraint"


# ---------------------------------------------------------------------------
# M10 — maxCostUnits denies on require_approval rules too
# ---------------------------------------------------------------------------


def test_m10_cost_cap_denies_on_require_approval_rule():
    policy = Policy(
        id="p",
        tenantId="t",
        name="n",
        createdAt="x",
        rules=[
            PolicyRule(
                id="cap",
                effect="require_approval",
                match={"upstream": "email", "tool": "send_email"},
                constraints={"maxCostUnits": 5},
            )
        ],
    )
    d = evaluate_policy(
        policy,
        ToolCallContext(upstream="email", tool="send_email", args={}, cost_units=100),
    )
    assert d.effect == "deny"
    assert d.source == "constraint"


# ---------------------------------------------------------------------------
# L4 — wildcard requires exactly ["*"]
# ---------------------------------------------------------------------------


def test_l4_wildcard_requires_exact_star_list():
    call = ToolCallContext(upstream="crm", tool="read_contact", args={}, cost_units=1)
    assert is_within_authorization(call, [AuthorizationDetail(upstream="crm", tools=["*"])])
    # A "*" mixed with a specific tool no longer means "all tools".
    assert not is_within_authorization(
        call, [AuthorizationDetail(upstream="crm", tools=["other", "*"])]
    )


# ---------------------------------------------------------------------------
# M3 — upstream base URL scheme / metadata validation
# ---------------------------------------------------------------------------


def test_m3_upstream_url_validation():
    # https always ok; loopback http ok; metadata blocked; remote http blocked in prod.
    _validate_upstream_base_url("https://crm.internal", allow_insecure=False)
    _validate_upstream_base_url("http://127.0.0.1:9000", allow_insecure=False)
    for bad in ("http://crm.internal", "http://169.254.169.254", "https://169.254.169.254", "ftp://x"):
        with pytest.raises(ToolgateError):
            _validate_upstream_base_url(bad, allow_insecure=False)
    # dev opt-in permits remote http
    _validate_upstream_base_url("http://crm.internal", allow_insecure=True)


# ---------------------------------------------------------------------------
# M5 / M7 / L5 / M8 (boundary) — server hardening
# ---------------------------------------------------------------------------


def test_m5_openapi_schema_disabled():
    ctx, client, *_ = _fresh_env()
    assert client.get("/openapi.json").status_code == 404


def test_m8_oversized_body_rejected():
    ctx, client, *_ = _fresh_env()
    big = "A" * 1_100_000
    r = client.post("/v1/gate/call/email", content=json.dumps({"tool": "x", "args": {"b": big}}),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_m8_deeply_nested_args_returns_400_not_500():
    # A valid-bearer call with a deeply nested *raw* body overflows the JSON
    # decode / canonical-hash path; it must surface as a clean 400, never an
    # uncaught 500. (An attacker sends raw bytes, not a client-encoded payload.)
    _ctx, _call, raw_call = _authed_env()
    depth = 60000
    body = '{"tool":"send_email","args":' + '{"a":' * depth + '1' + "}" * depth + "}"
    r = raw_call(body)
    # The regression: this used to be an uncaught 500 on a valid-bearer path.
    assert r.status_code == 400, r.status_code
    assert r.status_code != 500


def test_m8_normal_call_still_succeeds():
    _ctx, call, _raw = _authed_env()
    r = call({"to": "x@y.com"})
    assert r.status_code == 200


def test_l1_security_headers_present():
    ctx, client, *_ = _fresh_env()
    r = client.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_m7_sqlite_file_is_0600(tmp_path):
    db = tmp_path / "tg.db"
    Store(str(db))
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o600


def test_l5_mint_rejects_non_positive_ttl():
    kp = generate_ed25519_key_pair()
    with pytest.raises(ValueError):
        mint_capability_token(
            kp.private_jwk,
            issuer="i",
            audience="a",
            tenant_id="t",
            user_id="u",
            agent_id="ag",
            grant_id="g",
            scopes=[],
            authorization_details=[AuthorizationDetail(upstream="e", tools=["*"])],
            agent_jkt="x",
            ttl_seconds=0,
        )


# ---------------------------------------------------------------------------
# H1 — concurrent approval execution cannot double-fire the upstream
# ---------------------------------------------------------------------------


def test_h1_concurrent_approval_execution_is_single_shot():
    async def run() -> tuple[int, int, int]:
        upstream_calls: list[str] = []

        async def slow_handler(request: httpx.Request) -> httpx.Response:
            upstream_calls.append(str(request.url))
            await asyncio.sleep(0.3)
            return httpx.Response(200, json={"ok": True})

        ctx = create_app_context(
            db_path=":memory:",
            public_url=PUBLIC_URL,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(slow_handler)),
        )
        app = create_app(ctx)
        admin = {"x-toolgate-admin-key": ctx.config.admin_key}
        agent_keys = generate_ed25519_key_pair()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=PUBLIC_URL
        ) as c:
            async def post(path, body, headers=admin):
                r = await c.post(path, json=body, headers=headers)
                assert r.status_code < 300, r.text
                return r.json()

            tenant = (await post("/v1/control/tenants", {"name": "Acme"}))["id"]
            user = (await post("/v1/control/users", {"tenantId": tenant, "displayName": "S"}))["id"]
            agent = (
                await post(
                    "/v1/control/agents",
                    {"tenantId": tenant, "name": "a", "publicJwk": agent_keys.public_jwk},
                )
            )["id"]
            await post(
                "/v1/control/upstreams",
                {
                    "tenantId": tenant,
                    "name": "email",
                    "baseUrl": "https://mail.internal",
                    "credential": {"mode": "header", "headerName": "X-Api-Key", "secret": "k"},
                    "tools": [{"name": "send_email", "sideEffecting": True, "costUnits": 2}],
                },
            )
            policy = (
                await post(
                    "/v1/control/policies",
                    {
                        "tenantId": tenant,
                        "name": "p",
                        "rules": [
                            {
                                "id": "approve",
                                "effect": "require_approval",
                                "match": {"upstream": "email", "tool": "send_email"},
                            }
                        ],
                    },
                )
            )["id"]
            grant = (
                await post(
                    "/v1/control/grants",
                    {
                        "tenantId": tenant,
                        "userId": user,
                        "agentId": agent,
                        "policyId": policy,
                        "authorization": [{"upstream": "email", "tools": ["send_email"]}],
                        "budgetMaxUnits": 100,
                    },
                )
            )["id"]

            assertion = sign_client_assertion(
                agent_keys.private_jwk, agent_id=agent, token_url=f"{ctx.config.issuer}/v1/token"
            )
            tok = (
                await post(
                    "/v1/token",
                    {
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "client_assertion": assertion,
                        "grant_id": grant,
                    },
                    headers={},
                )
            )["access_token"]

            call_path = "/v1/gate/call/email"
            proof = sign_pop_proof(
                agent_keys.private_jwk, htm="POST", htu=f"{PUBLIC_URL}{call_path}", access_token=tok
            )
            r = await c.post(
                call_path,
                headers={"authorization": f"Bearer {tok}", "x-toolgate-proof": proof},
                json={"tool": "send_email", "args": {"to": "v@x.com"}},
            )
            approval_id = r.json()["approval_id"]
            await post(
                f"/v1/control/approvals/{approval_id}/decide",
                {"decision": "approve", "decidedBy": "boss"},
            )

            epath = f"/v1/gate/approvals/{approval_id}/execute"

            async def execute():
                p = sign_pop_proof(
                    agent_keys.private_jwk, htm="POST", htu=f"{PUBLIC_URL}{epath}", access_token=tok
                )
                return await c.post(
                    epath, headers={"authorization": f"Bearer {tok}", "x-toolgate-proof": p}
                )

            r1, r2 = await asyncio.gather(execute(), execute())
            spent = ctx.store.get_grant(grant).budget.spentUnits
            executed = sum(
                1 for r in (r1, r2) if r.status_code == 200 and r.json().get("status") == "executed"
            )
            return len(upstream_calls), executed, spent

    upstream_count, executed_count, spent = asyncio.run(run())
    assert upstream_count == 1, f"upstream fired {upstream_count} times"
    assert executed_count == 1, f"{executed_count} executes reported success"
    assert spent == 2, f"budget charged {spent}, expected 2"
