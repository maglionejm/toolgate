"""Adversary: holds a capability token exfiltrated from an MCP client.
Does NOT hold the agent key. Guarantee: blast radius = authorization_details
∩ policy ∩ budget ∩ TTL; revocation kills it immediately."""


def test_stolen_token_cannot_reach_undelegated_tools(target):
    grant = target.grant(authz=[{"upstream": "web", "tools": ["browse"]}])
    stolen = target.token(grant)
    listed = target.mcp_call(
        stolen, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    ).json()["result"]["tools"]
    assert {t["name"] for t in listed} == {"web__browse"}

    out = target.mcp_call(
        stolen,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "email__send_email", "arguments": {"to": "attacker@evil"}}},
    ).json()
    assert out["error"]["data"]["code"] == "TG_DENIED"
    assert target.ctx.store.list_audit(target.tenant)[-1].result.status == "denied"


def test_stolen_token_cannot_use_pop_surfaces(target):
    grant = target.grant()
    stolen = target.token(grant)
    # REST gate demands a proof the thief cannot sign.
    res = target.client.post(
        "/v1/gate/call/web",
        headers={"authorization": f"Bearer {stolen}", "content-type": "application/json"},
        content=b'{"tool": "browse", "args": {}}',
    )
    assert res.status_code == 401


def test_revocation_outruns_ttl(target):
    grant = target.grant()
    stolen = target.token(grant)
    target.post(f"/v1/control/grants/{grant}/revoke", {})
    out = target.mcp_call(
        stolen,
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "web__browse", "arguments": {}}},
    )
    assert out.status_code == 403


def test_budget_bounds_theft_spend(target):
    grant = target.grant(budget=2)
    stolen = target.token(grant)
    call = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "web__browse", "arguments": {}}}
    assert "result" in target.mcp_call(stolen, call).json()
    assert "result" in target.mcp_call(stolen, call).json()
    third = target.mcp_call(stolen, call).json()
    assert third["error"]["data"]["code"] == "TG_BUDGET_EXCEEDED"
