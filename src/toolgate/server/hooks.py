"""Public notification endpoints: Slack interactivity callbacks and email
magic links. Neither carries Toolgate credentials — Slack requests authenticate
via the channel's signing secret, links via single-use tokens bound to the
approval's args hash. Both decide through the same shared path as the console,
so operator attribution and audit records are identical."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from toolgate.core import (
    AuditAction,
    AuditActor,
    AuditDecision,
    AuditRecordInput,
    AuditResult,
    Connection,
    ToolgateError,
    hash_args,
    new_id,
)

from .approvals import decide_approval
from .context import AppContext
from .notifier import verify_slack_signature


def hooks_router(ctx: AppContext) -> APIRouter:
    router = APIRouter(prefix="/v1")

    # -- Slack interactivity ------------------------------------------------------

    @router.post("/hooks/slack")
    async def slack_interactivity(request: Request) -> JSONResponse:
        raw = await request.body()
        payload = _parse_slack_payload(raw)
        if payload is None:
            return JSONResponse(status_code=400, content={"text": "malformed payload"})
        action = (payload.get("actions") or [{}])[0]
        approval_id = action.get("value", "")
        decision = "approve" if action.get("action_id") == "tg_approve" else "deny"

        approval = ctx.store.get_approval(approval_id)
        if approval is None:
            return JSONResponse(status_code=404, content={"text": "unknown approval"})

        # Verify the Slack signature against the tenant's slack channel secrets.
        if not _verify_against_tenant_channels(ctx, approval.tenantId, request, raw):
            return JSONResponse(status_code=401, content={"text": "bad slack signature"})

        slack_user = (payload.get("user") or {}).get("id", "")
        binding = ctx.store.get_slack_binding(approval.tenantId, slack_user)
        if binding is None:
            return JSONResponse(
                content={
                    "response_type": "ephemeral",
                    "replace_original": False,
                    "text": (
                        "Your Slack user is not bound to a Toolgate operator. Ask an "
                        "owner to run: toolgate slack bind --tenant "
                        f"{approval.tenantId} --slack-user {slack_user or '<id>'} "
                        "--operator <op_id>"
                    ),
                }
            )
        operator = ctx.store.get_operator(binding.operatorId)
        if operator is None or operator.status != "active" or operator.role == "auditor":
            return JSONResponse(
                content={
                    "response_type": "ephemeral",
                    "replace_original": False,
                    "text": "Bound operator cannot decide approvals (missing, disabled, "
                    "or auditor role).",
                }
            )
        try:
            decided = decide_approval(
                ctx,
                approval,
                decision,
                decided_by=operator.id,
                decided_by_name=operator.name,
                via="slack",
            )
        except ToolgateError as err:
            return JSONResponse(
                content={
                    "response_type": "ephemeral",
                    "replace_original": False,
                    "text": f"Could not decide: {err.message}",
                }
            )
        return JSONResponse(
            content={
                "response_type": "ephemeral",
                "replace_original": False,
                "text": f"Approval {decided.id} {decided.status} by {operator.name}.",
            }
        )

    # -- email magic links --------------------------------------------------------

    @router.get("/approvals/link/{token}", response_class=HTMLResponse)
    async def approval_link(token: str) -> HTMLResponse:
        status, doc = ctx.store.consume_link_token(
            hashlib.sha256(token.encode()).hexdigest()
        )
        if status == "used":
            return _page("This link was already used. No state was changed.", 409)
        if status == "unknown" or doc is None:
            return _page("Unknown or invalid link.", 404)
        if datetime.fromisoformat(doc["expiresAt"]) < datetime.now(UTC):
            return _page("This link has expired. Nothing was decided.", 410)

        approval = ctx.store.get_approval(doc["approvalId"])
        if approval is None or approval.status != "pending":
            state = approval.status if approval else "gone"
            return _page(f"The approval is already {state}. Nothing was decided.", 409)
        # The link is bound to the exact args the human saw in the email.
        if hash_args(approval.args) != doc["argsHash"]:
            return _page("The approval's arguments changed; link refused.", 409)
        operator = ctx.store.get_operator(doc["operatorId"])
        if operator is None or operator.status != "active" or operator.role == "auditor":
            return _page("The operator bound to this link cannot decide approvals.", 403)
        try:
            decided = decide_approval(
                ctx,
                approval,
                doc["decision"],
                decided_by=operator.id,
                decided_by_name=operator.name,
                via="email",
            )
        except ToolgateError as err:
            return _page(f"Could not decide: {err.message}", 409)
        return _page(
            f"Approval {decided.id} {decided.status} "
            f"({approval.upstream}.{approval.tool}) — decided by {operator.name}."
        )

    # -- OAuth connection callback (#11) --------------------------------------------

    @router.get("/connections/callback", response_class=HTMLResponse)
    async def connections_callback(
        state: str = "", code: str = "", error: str = ""
    ) -> HTMLResponse:
        if error:
            return _page(f"The provider reported an error: {error}. Nothing was connected.", 400)
        if not state or not code:
            return _page("Missing state or code.", 400)
        assert ctx.broker is not None
        try:
            connection = await ctx.broker.complete(state, code)
        except ToolgateError as err:
            return _page(f"Could not complete the connection: {err.message}", 400)
        _connection_audit(ctx, connection)
        return _page(
            f"Connected. User {connection.userId} is now linked to provider app "
            f"{connection.providerAppId}; agents acting for this user can call the "
            f"gated tools. You can close this window."
        )

    def _verify_against_tenant_channels(
        ctx_: AppContext, tenant_id: str, request: Request, raw: bytes
    ) -> bool:
        timestamp = request.headers.get("x-slack-request-timestamp", "")
        signature = request.headers.get("x-slack-signature", "")
        for channel in ctx_.store.list_channels(tenant_id):
            if channel.config.type != "slack" or channel.status != "active":
                continue
            sealed = ctx_.store.get_secret(channel.config.signingSecretRef)
            if sealed is None:
                continue
            secret = ctx_.vault.open(sealed)
            if verify_slack_signature(secret, timestamp, raw, signature):
                return True
        return False

    return router


def _connection_audit(ctx: AppContext, connection: Connection) -> None:
    """Connection establishment lands in the signed chain like every other
    lifecycle event; the token material itself never does."""
    ctx.audit.record(
        AuditRecordInput(
            id=new_id("evt"),
            tenantId=connection.tenantId,
            ts=datetime.now(UTC).isoformat(),
            actor=AuditActor(
                agentId="control-plane", userId=connection.userId, grantId="-", tokenJti="-"
            ),
            action=AuditAction(
                callId=new_id("call"),
                upstream="control",
                tool="connections.connect",
                argsHash=hash_args(
                    {"id": connection.id, "providerAppId": connection.providerAppId}
                ),
            ),
            decision=AuditDecision(
                effect="allow",
                source="operator",
                reason=f"oauth connection completed by user {connection.userId}",
            ),
            result=AuditResult(status="executed"),
        )
    )


def _parse_slack_payload(raw: bytes) -> dict[str, Any] | None:
    try:
        form = parse_qs(raw.decode())
        return json.loads(form["payload"][0])
    except (ValueError, KeyError, UnicodeDecodeError):
        return None


def _page(message: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><meta charset='utf-8'><title>Toolgate</title>"
        f"<body style='font-family:system-ui;max-width:40rem;margin:4rem auto'>"
        f"<h3>Toolgate approvals</h3><p>{message}</p></body>",
        status_code=status_code,
    )
