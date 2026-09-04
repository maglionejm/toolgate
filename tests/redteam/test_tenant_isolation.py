"""Adversary: a fully legitimate agent of tenant A probing tenant B."""

from toolgate.core import sign_pop_proof

PUBLIC_URL = "http://testserver"


def test_foreign_tenant_upstream_invisible(target):
    other_tenant = target.post("/v1/control/tenants", {"name": "Other"})["id"]
    target.post(
        "/v1/control/upstreams",
        {
            "tenantId": other_tenant,
            "name": "secretcrm",
            "baseUrl": "https://b.internal",
            "credential": {"mode": "bearer", "secret": "b-secret"},
            "tools": [{"name": "read"}],
        },
    )
    grant = target.grant(authz=[{"upstream": "secretcrm", "tools": ["*"]}])
    token = target.token(grant)
    res = target.signed_call(token, "secretcrm", "read")
    assert res.status_code == 404  # resolution is tenant-scoped


def test_foreign_tenant_approval_untouchable(target):
    grant = target.grant()
    token = target.token(grant)
    assert target.signed_call(token, "web", "browse").status_code == 200
    parked = target.signed_call(token, "email", "send_email", {"to": "x@evil"})
    approval_id = parked.json()["approval_id"]

    # A different tenant's identical agent identity cannot poll it.
    other_tenant = target.post("/v1/control/tenants", {"name": "Mallory Inc"})["id"]
    o_user = target.post(
        "/v1/control/users", {"tenantId": other_tenant, "displayName": "M"}
    )["id"]
    o_agent = target.post(
        "/v1/control/agents",
        {"tenantId": other_tenant, "name": "m", "publicJwk": target.agent_keys.public_jwk},
    )["id"]
    o_policy = target.post(
        "/v1/control/policies",
        {"tenantId": other_tenant, "name": "p", "rules": [{"effect": "allow", "match": {}}]},
    )["id"]
    o_grant = target.post(
        "/v1/control/grants",
        {
            "tenantId": other_tenant,
            "userId": o_user,
            "agentId": o_agent,
            "policyId": o_policy,
            "authorization": [{"upstream": "web", "tools": ["*"]}],
            "budgetMaxUnits": 5,
        },
    )["id"]
    from toolgate.core import sign_client_assertion

    assertion = sign_client_assertion(
        target.agent_keys.private_jwk, agent_id=o_agent, token_url=f"{PUBLIC_URL}/v1/token"
    )
    o_token = target.client.post(
        "/v1/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_assertion": assertion,
            "grant_id": o_grant,
        },
    ).json()["access_token"]
    path = f"/v1/gate/approvals/{approval_id}"
    proof = sign_pop_proof(
        target.agent_keys.private_jwk, htm="GET",
        htu=f"{PUBLIC_URL}{path}", access_token=o_token,
    )
    res = target.client.get(
        path, headers={"authorization": f"Bearer {o_token}", "x-toolgate-proof": proof}
    )
    assert res.status_code == 403
