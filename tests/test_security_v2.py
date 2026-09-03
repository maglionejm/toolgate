"""Regression tests for the v0.4 security features: body-bound proofs (C1),
key rotation with lineage (C3), Merkle checkpoints (C4), taint policy (C5)."""

import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import (
    Checkpoint,
    generate_ed25519_key_pair,
    merkle_root,
    sign_client_assertion,
    sign_pop_proof,
    verify_audit_chain,
    verify_checkpoint,
)
from toolgate.server import create_app, create_app_context

PUBLIC_URL = "http://testserver"


class Env:
    def __init__(self) -> None:
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=PUBLIC_URL,
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": True}))
            ),
        )
        self.client = TestClient(create_app(self.ctx))
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
                "name": "web",
                "baseUrl": "https://web.internal",
                "credential": {"mode": "bearer", "secret": "web-key"},
                "tools": [
                    {"name": "browse", "costUnits": 1, "contentTrust": "untrusted_source"}
                ],
            },
        )
        self._post(
            "/v1/control/upstreams",
            {
                "tenantId": self.tenant,
                "name": "email",
                "baseUrl": "https://mail.internal",
                "credential": {"mode": "bearer", "secret": "mail-key"},
                "tools": [{"name": "send_email", "sideEffecting": True, "costUnits": 1}],
            },
        )
        self.policy = self._post(
            "/v1/control/policies",
            {
                "tenantId": self.tenant,
                "name": "taint-aware",
                "rules": [
                    {
                        "id": "tainted-email-needs-human",
                        "effect": "require_approval",
                        "match": {"upstream": "email", "tool": "send_email"},
                        "when": {"txnTouchedUntrusted": True},
                    },
                    {"id": "allow-all", "effect": "allow", "match": {}},
                ],
            },
        )["id"]

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def new_grant(self) -> str:
        return self._post(
            "/v1/control/grants",
            {
                "tenantId": self.tenant,
                "userId": self.user,
                "agentId": self.agent,
                "policyId": self.policy,
                "authorization": [
                    {"upstream": "web", "tools": ["*"]},
                    {"upstream": "email", "tools": ["*"]},
                ],
                "budgetMaxUnits": 50,
            },
        )["id"]

    def get_token(self, grant: str) -> str:
        assertion = sign_client_assertion(
            self.agent_keys.private_jwk, agent_id=self.agent, token_url=f"{PUBLIC_URL}/v1/token"
        )
        res = self.client.post(
            "/v1/token",
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_assertion": assertion,
                "grant_id": grant,
            },
        )
        assert res.status_code == 200, res.text
        return res.json()["access_token"]

    def call(
        self,
        token: str,
        upstream: str,
        tool: str,
        args: dict | None = None,
        *,
        sign_body: bytes | None = None,
        send_body: bytes | None = None,
        omit_cd: bool = False,
    ) -> httpx.Response:
        path = f"/v1/gate/call/{upstream}"
        body = json.dumps({"tool": tool, "args": args or {}}).encode()
        signed = sign_body if sign_body is not None else body
        proof = sign_pop_proof(
            self.agent_keys.private_jwk,
            htm="POST",
            htu=f"{PUBLIC_URL}{path}",
            access_token=token,
            body=None if omit_cd else signed,
        )
        return self.client.post(
            path,
            headers={
                "authorization": f"Bearer {token}",
                "x-toolgate-proof": proof,
                "content-type": "application/json",
            },
            content=send_body if send_body is not None else body,
        )


@pytest.fixture(scope="module")
def env() -> Env:
    return Env()


# --- C1: body-bound proofs ---------------------------------------------------


def test_body_substitution_rejected(env: Env) -> None:
    grant = env.new_grant()
    token = env.get_token(grant)
    signed = json.dumps({"tool": "send_email", "args": {"to": "friend@acme.com"}}).encode()
    swapped = json.dumps({"tool": "send_email", "args": {"to": "attacker@evil.com"}}).encode()
    res = env.call(
        token, "email", "send_email", sign_body=signed, send_body=swapped
    )
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "TG_PROOF_INVALID"


def test_missing_cd_rejected_when_required(env: Env) -> None:
    grant = env.new_grant()
    token = env.get_token(grant)
    res = env.call(token, "web", "browse", {"url": "https://x"}, omit_cd=True)
    assert res.status_code == 401


def test_bound_body_executes(env: Env) -> None:
    grant = env.new_grant()
    token = env.get_token(grant)
    res = env.call(token, "web", "browse", {"url": "https://news.example"})
    assert res.status_code == 200, res.text


# --- C5: taint policy ---------------------------------------------------------


def test_untainted_email_allowed_but_tainted_task_needs_human(env: Env) -> None:
    grant = env.new_grant()

    # Fresh token/task: email without touching untrusted content -> allow.
    token = env.get_token(grant)
    clean = env.call(token, "email", "send_email", {"to": "x@acme.com"})
    assert clean.status_code == 200, clean.text

    # Same task (same token txn): browse untrusted content first, then email
    # -> the when.txnTouchedUntrusted rule parks it for a human.
    token2 = env.get_token(grant)
    assert env.call(token2, "web", "browse", {"url": "https://evil.example"}).status_code == 200
    tainted = env.call(token2, "email", "send_email", {"to": "x@acme.com"})
    assert tainted.status_code == 202
    assert tainted.json()["status"] == "pending_approval"

    audit = env.ctx.store.list_audit(env.tenant)
    parked = audit[-1]
    assert parked.decision.ruleId == "tainted-email-needs-human"


# --- C3: key rotation ----------------------------------------------------------


def test_gate_rotation_keeps_chain_verifiable(env: Env) -> None:
    before = env.client.get("/v1/control/audit/verify", headers=env.admin).json()
    assert before["valid"] is True

    rotated = env._post("/v1/control/keys/rotate", {"plane": "gate"})
    new_kid = rotated["kid"]

    # Records signed under the new kid still verify (handoff lineage).
    grant = env.new_grant()
    token = env.get_token(grant)
    assert env.call(token, "web", "browse", {}).status_code == 200
    after = env.client.get("/v1/control/audit/verify", headers=env.admin).json()
    assert after["valid"] is True and after["length"] > before["length"]

    keys = env.client.get("/v1/keys").json()
    kids = [k["kid"] for k in keys["gate_jwks"]["keys"]]
    assert new_kid == kids[0] and len(kids) >= 2

    # Lineage is enforced: dropping the handoff record breaks verification.
    records = env.ctx.store.list_audit()
    no_handoff = [r for r in records if r.action.tool != "gate-key-rotation"]
    jwks = {k["kid"]: k for k in keys["gate_jwks"]["keys"]}
    # Re-link is impossible without re-hashing, so verification must fail fast.
    assert verify_audit_chain(no_handoff, jwks).valid is False


def test_control_rotation_old_and_new_tokens_verify(env: Env) -> None:
    grant = env.new_grant()
    old_token = env.get_token(grant)
    env._post("/v1/control/keys/rotate", {"plane": "control"})
    new_token = env.get_token(grant)
    assert env.call(old_token, "web", "browse", {}).status_code == 200
    assert env.call(new_token, "web", "browse", {}).status_code == 200


# --- C4: checkpoints -----------------------------------------------------------


def test_checkpoint_cut_and_verified(env: Env) -> None:
    cp = env._post("/v1/control/audit/checkpoint", {})
    records = env.ctx.store.list_audit()
    assert cp["seq"] == len(records)
    assert cp["root"] == merkle_root([r.hash for r in records])

    verify = env.client.get("/v1/control/audit/verify", headers=env.admin).json()
    assert verify["checkpoints_total"] >= 1
    assert verify["checkpoints_valid"] == verify["checkpoints_total"]


def test_checkpoint_detects_history_rewrite(env: Env) -> None:
    cp_raw = env._post("/v1/control/audit/checkpoint", {})
    cp = Checkpoint.model_validate(cp_raw)
    records = env.ctx.store.list_audit()
    jwks = env.ctx.audit.verify_jwks()
    assert verify_checkpoint(cp, records, jwks) is True

    # Rewriting an early record (even with valid re-linking elsewhere) changes
    # the Merkle root: the anchored checkpoint no longer matches.
    tampered = [r.model_copy(deep=True) for r in records]
    tampered[0] = tampered[0].model_copy(update={"hash": "f" * 64})
    assert verify_checkpoint(cp, tampered, jwks) is False
