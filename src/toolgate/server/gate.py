import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from toolgate.core import (
    ApprovalRequest,
    AuditAction,
    AuditActor,
    AuditDecision,
    AuditRecordInput,
    AuditResult,
    CapabilityClaims,
    Decision,
    DelegationGrant,
    ErrorCodes,
    ToolCallContext,
    ToolDef,
    ToolgateError,
    Upstream,
    decide,
    hash_args,
    new_id,
    verify_capability_token,
    verify_pop_proof,
)

from .context import AppContext


class CallBody(BaseModel):
    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class AuthedCall:
    claims: CapabilityClaims
    grant: DelegationGrant


def _now() -> str:
    return datetime.now(UTC).isoformat()


def gate_router(ctx: AppContext) -> APIRouter:
    router = APIRouter(prefix="/v1/gate")

    @router.post("/call/{upstream_name}")
    async def call_tool(upstream_name: str, body: CallBody, request: Request) -> Any:
        authed = await _authenticate(ctx, request, f"/v1/gate/call/{upstream_name}")
        claims, grant = authed.claims, authed.grant
        if not ctx.gate_limiter.allow(grant.id):
            raise ToolgateError(
                ErrorCodes.RATE_LIMITED, "gate call rate limit exceeded for this grant"
            )
        upstream, tool_def = _resolve_tool(ctx, claims.tenant, upstream_name, body.tool)

        call_id = new_id("call")
        call = ToolCallContext(
            upstream=upstream_name, tool=body.tool, args=body.args, cost_units=tool_def.costUnits
        )
        policy = ctx.store.get_policy(grant.policyId)
        if not policy:
            raise ToolgateError(ErrorCodes.INTERNAL, "grant policy missing")

        decision = decide(policy, call, claims.authorization_details)
        actor = AuditActor(
            agentId=claims.act.sub, userId=claims.sub, grantId=grant.id, tokenJti=claims.jti
        )
        action = AuditAction(
            callId=call_id, upstream=upstream_name, tool=body.tool, argsHash=hash_args(body.args)
        )

        if decision.effect == "deny":
            ctx.audit.record(
                AuditRecordInput(
                    id=new_id("evt"),
                    tenantId=claims.tenant,
                    ts=_now(),
                    actor=actor,
                    action=action,
                    decision=_to_audit_decision(decision),
                    result=AuditResult(status="denied"),
                )
            )
            details: dict[str, Any] = {"source": decision.source}
            if decision.rule_id:
                details["ruleId"] = decision.rule_id
            raise ToolgateError(ErrorCodes.DENIED, decision.reason, details)

        if decision.effect == "require_approval":
            approval = ApprovalRequest(
                id=new_id("apr"),
                tenantId=claims.tenant,
                callId=call_id,
                grantId=grant.id,
                agentId=claims.act.sub,
                userId=claims.sub,
                upstream=upstream_name,
                tool=body.tool,
                args=body.args,
                status="pending",
                requestedAt=_now(),
                expiresAt=(
                    datetime.now(UTC) + timedelta(seconds=ctx.config.approval_ttl_seconds)
                ).isoformat(),
            )
            ctx.store.put_approval(approval)
            ctx.store.prune_approvals()
            ctx.audit.record(
                AuditRecordInput(
                    id=new_id("evt"),
                    tenantId=claims.tenant,
                    ts=_now(),
                    actor=actor,
                    action=action,
                    decision=_to_audit_decision(decision),
                    result=AuditResult(status="pending_approval"),
                )
            )
            return JSONResponse(
                status_code=202,
                content={
                    "status": "pending_approval",
                    "approval_id": approval.id,
                    "expires_at": approval.expiresAt,
                    "reason": decision.reason,
                },
            )

        result = await _execute_call(
            ctx,
            actor=actor,
            action=action,
            decision=_to_audit_decision(decision),
            grant=grant,
            upstream=upstream,
            tool_def=tool_def,
            tool=body.tool,
            args=body.args,
        )
        return {"status": "executed", "call_id": call_id, "result": result}

    @router.get("/approvals/{approval_id}")
    async def approval_status(approval_id: str, request: Request) -> dict[str, Any]:
        # Require the PoP proof like every other gate endpoint: a stolen bearer
        # token alone must not be able to enumerate approval state.
        authed = await _authenticate(ctx, request, f"/v1/gate/approvals/{approval_id}")
        approval = _require_approval(ctx, approval_id, authed.claims)
        return {
            "approval_id": approval.id,
            "status": approval.status,
            "expires_at": approval.expiresAt,
        }

    @router.post("/approvals/{approval_id}/execute")
    async def execute_approval(approval_id: str, request: Request) -> dict[str, Any]:
        authed = await _authenticate(ctx, request, f"/v1/gate/approvals/{approval_id}/execute")
        claims, grant = authed.claims, authed.grant
        approval = _require_approval(ctx, approval_id, claims)

        if approval.status == "pending":
            raise ToolgateError(ErrorCodes.APPROVAL_PENDING, "approval still pending")
        if approval.status != "approved":
            raise ToolgateError(ErrorCodes.APPROVAL_DENIED, f"approval is {approval.status}")
        if datetime.fromisoformat(approval.expiresAt) < datetime.now(UTC):
            approval.status = "expired"
            ctx.store.put_approval(approval)
            raise ToolgateError(ErrorCodes.APPROVAL_DENIED, "approval expired before execution")

        # Resolve (read-only) before claiming, so an unknown-upstream error can't
        # strand the claim.
        upstream, tool_def = _resolve_tool(ctx, claims.tenant, approval.upstream, approval.tool)

        # Atomically claim the approval *before* the upstream call. If two
        # requests race, only one wins the approved->executing transition; the
        # loser is rejected instead of firing the side effect a second time.
        if not ctx.store.claim_approval_for_execution(approval.id):
            current = ctx.store.get_approval(approval.id)
            state = current.status if current else "unknown"
            raise ToolgateError(
                ErrorCodes.APPROVAL_DENIED,
                f"approval is {state} (already executing or executed)",
            )

        # The stored args are the approved args — the agent cannot substitute them.
        actor = AuditActor(
            agentId=claims.act.sub, userId=claims.sub, grantId=grant.id, tokenJti=claims.jti
        )
        action = AuditAction(
            callId=approval.callId,
            upstream=approval.upstream,
            tool=approval.tool,
            argsHash=hash_args(approval.args),
        )
        decision = AuditDecision(
            effect="allow",
            source="approval",
            reason=f"approved by {approval.decidedBy or 'unknown'} at {approval.decidedAt or '?'}",
        )

        try:
            result = await _execute_call(
                ctx,
                actor=actor,
                action=action,
                decision=decision,
                grant=grant,
                upstream=upstream,
                tool_def=tool_def,
                tool=approval.tool,
                args=approval.args,
            )
        except Exception:
            # Nothing succeeded upstream — release the claim so a retry is possible.
            ctx.store.revert_approval_claim(approval.id)
            raise

        approval.status = "executed"
        approval.executedAt = _now()
        ctx.store.put_approval(approval)
        return {"status": "executed", "call_id": approval.callId, "result": result}

    return router


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------


async def _authenticate_token_only(ctx: AppContext, request: Request) -> AuthedCall:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise ToolgateError(ErrorCodes.TOKEN_INVALID, "missing bearer capability token")
    token = auth[7:].strip()
    claims = verify_capability_token(
        ctx.control_verify_jwk,
        token,
        issuer=ctx.config.issuer,
        audience=ctx.config.gate_audience,
    )

    grant = ctx.store.get_grant(claims.grant_id)
    if not grant:
        raise ToolgateError(ErrorCodes.NOT_FOUND, "grant no longer exists")
    if grant.status != "active":
        # Live tokens die with their grant: revocation is immediate.
        raise ToolgateError(ErrorCodes.REVOKED, "grant revoked")
    if datetime.fromisoformat(grant.expiresAt) < datetime.now(UTC):
        raise ToolgateError(ErrorCodes.TOKEN_EXPIRED, "grant expired")
    agent = ctx.store.get_agent(claims.act.sub)
    if not agent or agent.status != "active":
        raise ToolgateError(ErrorCodes.REVOKED, "agent unknown or disabled")
    return AuthedCall(claims=claims, grant=grant)


async def _authenticate(ctx: AppContext, request: Request, path: str) -> AuthedCall:
    authed = await _authenticate_token_only(ctx, request)
    proof = request.headers.get("x-toolgate-proof")
    if not proof:
        raise ToolgateError(ErrorCodes.PROOF_INVALID, "missing x-toolgate-proof header")

    token = request.headers.get("authorization", "")[7:].strip()
    verified = verify_pop_proof(
        proof,
        expected_jkt=authed.claims.cnf.jkt,
        htm=request.method,
        htu=f"{ctx.config.public_url}{path}",
        access_token=token,
    )
    if not ctx.store.consume_jti(verified.jti, "proof", 120):
        raise ToolgateError(ErrorCodes.PROOF_INVALID, "proof replayed")
    return authed


def _resolve_tool(
    ctx: AppContext, tenant_id: str, upstream_name: str, tool: str
) -> tuple[Upstream, ToolDef]:
    upstream = ctx.store.find_upstream_by_name(tenant_id, upstream_name)
    if not upstream:
        raise ToolgateError(ErrorCodes.NOT_FOUND, f"unknown upstream: {upstream_name}")
    tool_def = next((t for t in upstream.tools if t.name == tool), None)
    if not tool_def:
        raise ToolgateError(
            ErrorCodes.NOT_FOUND, f"unknown tool {tool} on upstream {upstream_name}"
        )
    return upstream, tool_def


def _require_approval(
    ctx: AppContext, approval_id: str, claims: CapabilityClaims
) -> ApprovalRequest:
    approval = ctx.store.get_approval(approval_id)
    if not approval:
        raise ToolgateError(ErrorCodes.NOT_FOUND, f"approval not found: {approval_id}")
    if approval.grantId != claims.grant_id or approval.tenantId != claims.tenant:
        raise ToolgateError(ErrorCodes.DENIED, "approval belongs to a different grant")
    return approval


async def _execute_call(
    ctx: AppContext,
    *,
    actor: AuditActor,
    action: AuditAction,
    decision: AuditDecision,
    grant: DelegationGrant,
    upstream: Upstream,
    tool_def: ToolDef,
    tool: str,
    args: dict[str, Any],
) -> Any:
    def audit(result: AuditResult, dec: AuditDecision = decision) -> None:
        ctx.audit.record(
            AuditRecordInput(
                id=new_id("evt"),
                tenantId=grant.tenantId,
                ts=_now(),
                actor=actor,
                action=action,
                decision=dec,
                result=result,
            )
        )

    if not ctx.store.charge_budget(grant.id, tool_def.costUnits):
        audit(
            AuditResult(status="denied"),
            AuditDecision(
                effect="deny",
                source="budget",
                reason=f"budget exhausted (cost {tool_def.costUnits})",
            ),
        )
        raise ToolgateError(
            ErrorCodes.BUDGET_EXCEEDED,
            "delegation grant budget exhausted",
            {"costUnits": tool_def.costUnits},
        )

    sealed = ctx.store.get_secret(upstream.credential.secretRef)
    if not sealed:
        raise ToolgateError(ErrorCodes.INTERNAL, "upstream credential missing from vault")
    secret = ctx.vault.open(sealed)

    url = f"{upstream.baseUrl.rstrip('/')}/tools/{tool}"
    headers: dict[str, str] = {"content-type": "application/json"}
    params: dict[str, str] = {}
    cred = upstream.credential
    if cred.mode == "bearer":
        headers["authorization"] = f"Bearer {secret}"
    elif cred.mode == "header":
        headers[cred.headerName.lower()] = secret
    else:
        params[cred.paramName] = secret

    started = time.monotonic()
    try:
        response = await ctx.http.post(url, headers=headers, params=params, json=args)
    except httpx.HTTPError as err:
        audit(AuditResult(status="error", latencyMs=(time.monotonic() - started) * 1000))
        raise ToolgateError(ErrorCodes.UPSTREAM_ERROR, f"upstream unreachable: {err}") from err

    latency_ms = (time.monotonic() - started) * 1000
    try:
        body = response.json()
    except ValueError:
        body = {"raw": "non-JSON upstream response"}

    if response.status_code >= 400:
        audit(
            AuditResult(status="error", httpStatus=response.status_code, latencyMs=latency_ms)
        )
        raise ToolgateError(
            ErrorCodes.UPSTREAM_ERROR, f"upstream returned {response.status_code}"
        )

    audit(
        AuditResult(
            status="executed",
            httpStatus=response.status_code,
            latencyMs=latency_ms,
            costUnits=tool_def.costUnits,
        )
    )
    return body


def _to_audit_decision(decision: Decision) -> AuditDecision:
    return AuditDecision(
        effect=decision.effect,
        source=decision.source,
        ruleId=decision.rule_id,
        reason=decision.reason,
    )
