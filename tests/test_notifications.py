"""Approval push channels (#13, spec: add-approvals-push-channels).

All external effects are faked: webhook and Slack traffic goes through an
httpx MockTransport, email through a captured mailer. The notifier runs inline
so every assertion is deterministic.
"""

import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.core import verify_detached_jws
from toolgate.sdk import PendingApproval, ToolgateClient
from toolgate.server import create_app, create_app_context

BASE = "http://testserver"
WEBHOOK_URL = "https://hooks.example/toolgate"
SLACK_SIGNING_SECRET = "slack-signing-secret"  # noqa: S105 - test fixture


class FakeExternals:
    """Records webhook/Slack requests; scriptable webhook failures."""

    def __init__(self) -> None:
        self.webhook_requests: list[httpx.Request] = []
        self.slack_posts: list[dict[str, Any]] = []
        self.slack_updates: list[dict[str, Any]] = []
        self.webhook_fail = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(WEBHOOK_URL):
            self.webhook_requests.append(request)
            if self.webhook_fail:
                return httpx.Response(500, json={"error": "down"})
            return httpx.Response(200, json={"ok": True})
        if url.endswith("/chat.postMessage"):
            self.slack_posts.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True, "ts": "111.222", "channel": "C123"})
        if url.endswith("/chat.update"):
            self.slack_updates.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"error": f"unrouted {url}"})


class Env:
    def __init__(self) -> None:
        self.externals = FakeExternals()
        self.emails: list[dict[str, Any]] = []
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=BASE,
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": 1}))
            ),
            notify_http=httpx.Client(transport=httpx.MockTransport(self.externals.handler)),
            mailer=lambda **kw: self.emails.append(kw),
        )
        assert self.ctx.notifier is not None
        self.ctx.notifier.inline = True
        self.app = create_app(self.ctx)
        self.client = TestClient(self.app)
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}

        from toolgate.core import generate_ed25519_key_pair

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
                "tools": [{"name": "wire_money", "sideEffecting": True, "costUnits": 2}],
            },
        )
        policy = self._post(
            "/v1/control/policies",
            {
                "tenantId": self.tenant,
                "name": "p",
                "rules": [
                    {"id": "human-wire", "effect": "require_approval",
                     "match": {"tool": "wire_money"}},
                    {"id": "ok", "effect": "allow", "match": {}},
                ],
            },
        )["id"]
        self.grant = self._post(
            "/v1/control/grants",
            {
                "tenantId": self.tenant,
                "userId": self.user,
                "agentId": self.agent,
                "policyId": policy,
                "authorization": [{"upstream": "crm", "tools": ["*"]}],
                "budgetMaxUnits": 40,
            },
        )["id"]
        created = self._post("/v1/control/operators", {"name": "Ana", "role": "approver"})
        self.operator = created["operator"]["id"]
        self.operator_key = created["key"]

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body)
        assert res.status_code < 300, res.text
        return res.json()

    def add_webhook_channel(self) -> str:
        return self._post(
            "/v1/control/channels",
            {"tenantId": self.tenant, "name": "hooks", "type": "webhook", "url": WEBHOOK_URL},
        )["id"]

    def add_slack_channel(self) -> str:
        return self._post(
            "/v1/control/channels",
            {
                "tenantId": self.tenant,
                "name": "slack",
                "type": "slack",
                "slackChannel": "C123",
                "botToken": "xoxb-test-token",
                "signingSecret": SLACK_SIGNING_SECRET,
            },
        )["id"]

    def add_email_channel(self) -> str:
        return self._post(
            "/v1/control/channels",
            {
                "tenantId": self.tenant,
                "name": "mail",
                "type": "email",
                "smtpHost": "smtp.example",
                "fromAddress": "toolgate@acme.example",
                "recipients": [{"email": "ana@acme.example", "operatorId": self.operator}],
            },
        )["id"]

    def sdk(self) -> ToolgateClient:
        outer = self

        class Bridge(httpx.Client):
            def request(inner, method: str, url: Any, **kw: Any) -> httpx.Response:  # noqa: N805
                return outer.client.request(method, str(url), **kw)

        return ToolgateClient(
            base_url=BASE,
            agent_id=self.agent,
            agent_private_jwk=self.agent_keys.private_jwk,
            grant_id=self.grant,
            http_client=Bridge(),
        )

    def park(self) -> PendingApproval:
        parked = self.sdk().call("crm", "wire_money", {"amount": 99, "to": "acct-7"})
        assert isinstance(parked, PendingApproval)
        return parked

    def slack_click(
        self, approval_id: str, action: str, slack_user: str, *, secret: str | None = None
    ) -> httpx.Response:
        payload = {
            "type": "block_actions",
            "user": {"id": slack_user},
            "actions": [{"action_id": action, "value": approval_id}],
        }
        body = urlencode({"payload": json.dumps(payload)}).encode()
        ts = str(int(time.time()))
        digest = hmac.new(
            (secret or SLACK_SIGNING_SECRET).encode(), b"v0:" + ts.encode() + b":" + body,
            hashlib.sha256,
        ).hexdigest()
        return self.client.post(
            "/v1/hooks/slack",
            content=body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts,
                "x-slack-signature": f"v0={digest}",
            },
        )


@pytest.fixture()
def env() -> Env:
    return Env()


# --- fan-out and webhook signing ------------------------------------------------------


def test_parked_approval_fans_out_to_all_channels(env: Env) -> None:
    env.add_webhook_channel()
    env.add_slack_channel()
    env.add_email_channel()
    parked = env.park()

    deliveries = env.ctx.store.deliveries_for_approval(parked.approval_id)
    assert {d.channelType for d in deliveries} == {"webhook", "slack", "email"}
    assert all(d.status == "delivered" for d in deliveries)

    # Webhook: detached JWS verifies against the gate JWKS on the exact bytes.
    req = env.externals.webhook_requests[0]
    assert verify_detached_jws(
        req.headers["x-toolgate-signature"], req.content, env.ctx.audit.verify_jwks()
    )
    assert req.headers["x-toolgate-delivery"].startswith("dlv_")
    body = json.loads(req.content)
    assert body["event"] == "approval.parked"
    assert body["approval"]["id"] == parked.approval_id

    # Tampered payload must not verify.
    assert not verify_detached_jws(
        req.headers["x-toolgate-signature"], req.content + b"x", env.ctx.audit.verify_jwks()
    )

    # Slack: Block Kit message with actionable buttons rendering the exact args.
    blocks = env.externals.slack_posts[0]["blocks"]
    actions = next(b for b in blocks if b["type"] == "actions")
    assert {e["action_id"] for e in actions["elements"]} == {"tg_approve", "tg_deny"}
    assert '"amount": 99' in blocks[1]["text"]["text"]

    # Email: one message with approve and deny magic links.
    assert env.emails[0]["to"] == "ana@acme.example"
    assert f"{BASE}/v1/approvals/link/" in env.emails[0]["body"]


def test_webhook_down_retries_with_backoff_then_fails(env: Env) -> None:
    env.add_webhook_channel()
    env.externals.webhook_fail = True
    parked = env.park()

    delivery = env.ctx.store.deliveries_for_approval(parked.approval_id)[0]
    assert delivery.status == "pending"
    assert delivery.attempts == 1
    assert delivery.nextAttemptAt > delivery.createdAt  # backoff pushed it out

    # Drive the retry loop to exhaustion (advance time far past every backoff).
    far_future = int(time.time() * 1000) + 10_000_000
    for _ in range(10):
        env.ctx.notifier.process_due(now_ms=far_future)
    delivery = env.ctx.store.deliveries_for_approval(parked.approval_id)[0]
    assert delivery.status == "failed"
    assert delivery.attempts == 6  # MAX_ATTEMPTS

    # The approval itself is unaffected by delivery failures.
    approval = env.ctx.store.get_approval(parked.approval_id)
    assert approval is not None and approval.status == "pending"

    # Recovery path: a fresh parked approval delivers once the endpoint is back.
    env.externals.webhook_fail = False
    parked2 = env.park()
    assert env.ctx.store.deliveries_for_approval(parked2.approval_id)[0].status == "delivered"


# --- Slack decisions ------------------------------------------------------------------


def test_slack_approve_with_bound_operator(env: Env) -> None:
    env.add_slack_channel()
    env._post(
        "/v1/control/slack-bindings",
        {"tenantId": env.tenant, "slackUserId": "U777", "operatorId": env.operator},
    )
    parked = env.park()

    res = env.slack_click(parked.approval_id, "tg_approve", "U777")
    assert res.status_code == 200, res.text

    approval = env.ctx.store.get_approval(parked.approval_id)
    assert approval is not None
    assert approval.status == "approved"
    assert approval.decidedBy == env.operator

    # Ops audit record identical in shape to a console decision.
    records = [r for r in env.ctx.store.list_audit() if r.action.tool == "approvals.approve"]
    assert records and records[-1].decision.source == "operator"
    assert records[-1].actor.userId == env.operator
    assert "via slack" in records[-1].decision.reason

    # Decided fan-out updated the Slack message and deactivated the buttons.
    assert env.externals.slack_updates
    updated_blocks = env.externals.slack_updates[0]["blocks"]
    assert all(b["type"] != "actions" for b in updated_blocks)


def test_slack_unbound_user_refused_with_guidance(env: Env) -> None:
    env.add_slack_channel()
    parked = env.park()
    res = env.slack_click(parked.approval_id, "tg_approve", "U_UNBOUND")
    assert res.status_code == 200
    assert "not bound to a Toolgate operator" in res.json()["text"]
    approval = env.ctx.store.get_approval(parked.approval_id)
    assert approval is not None and approval.status == "pending"


def test_slack_bad_signature_rejected(env: Env) -> None:
    env.add_slack_channel()
    parked = env.park()
    res = env.slack_click(parked.approval_id, "tg_approve", "U777", secret="wrong-secret")
    assert res.status_code == 401
    approval = env.ctx.store.get_approval(parked.approval_id)
    assert approval is not None and approval.status == "pending"


def test_console_decision_updates_slack_message(env: Env) -> None:
    env.add_slack_channel()
    parked = env.park()
    res = env.client.post(
        f"/v1/control/approvals/{parked.approval_id}/decide",
        headers=env.admin,
        json={"decision": "deny"},
    )
    assert res.status_code == 200, res.text
    assert env.externals.slack_updates, "decision elsewhere must update the Slack message"
    assert all(b["type"] != "actions" for b in env.externals.slack_updates[0]["blocks"])


# --- email magic links ----------------------------------------------------------------


def _links_from_email(body: str) -> dict[str, str]:
    lines = {line.split(": ", 1)[0].strip(): line.split(": ", 1)[1].strip()
             for line in body.splitlines() if ": " in line and "/v1/approvals/link/" in line}
    return {"approve": lines["Approve"], "deny": lines["Deny"]}


def test_magic_link_single_use(env: Env) -> None:
    env.add_email_channel()
    parked = env.park()
    links = _links_from_email(env.emails[0]["body"])

    first = env.client.get(links["approve"].removeprefix(BASE))
    assert first.status_code == 200
    approval = env.ctx.store.get_approval(parked.approval_id)
    assert approval is not None
    assert approval.status == "approved"
    assert approval.decidedBy == env.operator

    # Replayed link: no state change, explicit already-used response.
    replay = env.client.get(links["approve"].removeprefix(BASE))
    assert replay.status_code == 409
    assert "already used" in replay.text
    approval = env.ctx.store.get_approval(parked.approval_id)
    assert approval is not None and approval.status == "approved"

    # The deny link is now inert too: the approval is no longer pending.
    deny = env.client.get(links["deny"].removeprefix(BASE))
    assert deny.status_code == 409
    approval = env.ctx.store.get_approval(parked.approval_id)
    assert approval is not None and approval.status == "approved"


def test_expired_magic_link_decides_nothing(env: Env) -> None:
    env.add_email_channel()
    parked = env.park()
    links = _links_from_email(env.emails[0]["body"])
    token = links["approve"].rsplit("/", 1)[1]

    # Force the token past its expiry (bound to the approval's own expiry).
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = env.ctx.store.db.execute(
        "SELECT json FROM link_tokens WHERE token_hash = ?", (token_hash,)
    ).fetchone()
    doc = json.loads(row[0])
    doc["expiresAt"] = "2000-01-01T00:00:00+00:00"
    env.ctx.store.db.execute(
        "UPDATE link_tokens SET json = ? WHERE token_hash = ?", (json.dumps(doc), token_hash)
    )

    res = env.client.get(links["approve"].removeprefix(BASE))
    assert res.status_code == 410
    approval = env.ctx.store.get_approval(parked.approval_id)
    assert approval is not None and approval.status == "pending"


# --- attribution parity and surfaces --------------------------------------------------


def test_attribution_parity_console_vs_channels(env: Env) -> None:
    env.add_slack_channel()
    env.add_email_channel()
    env._post(
        "/v1/control/slack-bindings",
        {"tenantId": env.tenant, "slackUserId": "U777", "operatorId": env.operator},
    )

    a1 = env.park()
    env.client.post(
        f"/v1/control/approvals/{a1.approval_id}/decide",
        headers=env.admin,
        json={"decision": "approve", "decidedBy": env.operator},
    )
    a2 = env.park()
    env.slack_click(a2.approval_id, "tg_approve", "U777")
    env.park()
    links = _links_from_email(env.emails[-1]["body"])
    env.client.get(links["approve"].removeprefix(BASE))

    records = [r for r in env.ctx.store.list_audit() if r.action.tool == "approvals.approve"]
    assert len(records) == 3
    for record in records:
        assert record.decision.source == "operator"
        assert record.decision.effect == "allow"
        assert record.actor.agentId == "control-plane"
        assert record.result.status == "executed"
    # Channel decisions carry the same operator attribution as console ones.
    assert records[1].actor.userId == env.operator
    assert records[2].actor.userId == env.operator


def test_deliveries_endpoint_lists_status(env: Env) -> None:
    env.add_webhook_channel()
    parked = env.park()
    res = env.client.get(
        f"/v1/control/approvals/{parked.approval_id}/deliveries", headers=env.admin
    )
    assert res.status_code == 200
    rows = res.json()
    assert rows and rows[0]["status"] == "delivered" and rows[0]["channelType"] == "webhook"


def test_channel_secrets_never_leave_the_vault(env: Env) -> None:
    env.add_slack_channel()
    listed = env.client.get(
        f"/v1/control/channels?tenantId={env.tenant}", headers=env.admin
    ).json()
    dumped = json.dumps(listed)
    assert "xoxb-test-token" not in dumped
    assert SLACK_SIGNING_SECRET not in dumped
    assert listed[0]["config"]["botTokenRef"].startswith("sec_")
