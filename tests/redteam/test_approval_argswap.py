"""Adversary: agent (key+grant) trying to execute something other than what
the human approved, or to reuse a decision."""

import json

from toolgate.core import sign_pop_proof

PUBLIC_URL = "http://testserver"


def _park(target, grant, token):
    res = target.signed_call(token, "email", "send_email", {"to": "x@evil"})
    assert res.status_code == 202
    return res.json()["approval_id"]


def _execute(target, token, approval_id):
    path = f"/v1/gate/approvals/{approval_id}/execute"
    proof = sign_pop_proof(
        target.agent_keys.private_jwk, htm="POST",
        htu=f"{PUBLIC_URL}{path}", access_token=token,
    )
    return target.client.post(
        path, headers={"authorization": f"Bearer {token}", "x-toolgate-proof": proof}
    )


def test_no_argument_resubmission_channel(target):
    """Execution has no body: the gate only ever runs the STORED args."""
    grant = target.grant()
    token = target.token(grant)
    # Taint the task so send_email parks.
    assert target.signed_call(token, "web", "browse").status_code == 200
    approval_id = _park(target, grant, token)
    target.post(f"/v1/control/approvals/{approval_id}/decide", {"decision": "approve"})

    path = f"/v1/gate/approvals/{approval_id}/execute"
    body = json.dumps({"args": {"to": "attacker@evil", "body": "exfil"}}).encode()
    proof = sign_pop_proof(
        target.agent_keys.private_jwk, htm="POST",
        htu=f"{PUBLIC_URL}{path}", access_token=token, body=body,
    )
    res = target.client.post(
        path,
        headers={
            "authorization": f"Bearer {token}",
            "x-toolgate-proof": proof,
            "content-type": "application/json",
        },
        content=body,
    )
    # Whatever the transport allows, the executed args are the approved ones.
    if res.status_code == 200:
        record = target.ctx.store.list_audit(target.tenant)[-1]
        from toolgate.core import hash_args

        assert record.action.argsHash == hash_args({"to": "x@evil"})


def test_denied_approval_never_executes(target):
    grant = target.grant()
    token = target.token(grant)
    assert target.signed_call(token, "web", "browse").status_code == 200
    approval_id = _park(target, grant, token)
    target.post(f"/v1/control/approvals/{approval_id}/decide", {"decision": "deny"})
    assert _execute(target, token, approval_id).status_code == 403


def test_foreign_grant_cannot_touch_approval(target):
    grant_a, grant_b = target.grant(), target.grant()
    token_a = target.token(grant_a)
    assert target.signed_call(token_a, "web", "browse").status_code == 200
    approval_id = _park(target, grant_a, token_a)
    target.post(f"/v1/control/approvals/{approval_id}/decide", {"decision": "approve"})
    token_b = target.token(grant_b)
    res = _execute(target, token_b, approval_id)
    assert res.status_code == 403
