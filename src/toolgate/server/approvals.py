"""Shared approval decision logic. The console endpoint, Slack interactivity,
and email magic links all decide through here, so attribution and audit shape
are identical no matter where the human clicked."""

from datetime import UTC, datetime
from typing import Any

from toolgate.core import (
    ApprovalRequest,
    AuditAction,
    AuditActor,
    AuditDecision,
    AuditRecordInput,
    AuditResult,
    ErrorCodes,
    ToolgateError,
    hash_args,
    new_id,
)

from .context import AppContext


def decide_approval(
    ctx: AppContext,
    approval: ApprovalRequest,
    decision: str,
    *,
    decided_by: str,
    decided_by_name: str,
    via: str,
) -> ApprovalRequest:
    """Flip a pending approval, append the ops audit record, and fan out the
    decision to notification channels. Raises on non-pending or expired."""
    if approval.status != "pending":
        raise ToolgateError(ErrorCodes.VALIDATION, f"approval is {approval.status}, not pending")
    if datetime.fromisoformat(approval.expiresAt) < datetime.now(UTC):
        approval.status = "expired"
        ctx.store.put_approval(approval)
        if ctx.notifier:
            ctx.notifier.fanout(approval, "expired")
        raise ToolgateError(ErrorCodes.VALIDATION, "approval expired")

    approval.status = "approved" if decision == "approve" else "denied"
    approval.decidedAt = datetime.now(UTC).isoformat()
    approval.decidedBy = decided_by
    ctx.store.put_approval(approval)
    _decision_audit(ctx, approval, decision, decided_by, decided_by_name, via)
    if ctx.notifier:
        ctx.notifier.fanout(approval, "decided")
    return approval


def _decision_audit(
    ctx: AppContext,
    approval: ApprovalRequest,
    decision: str,
    decided_by: str,
    decided_by_name: str,
    via: str,
) -> None:
    payload: dict[str, Any] = {
        "id": approval.id,
        "tool": f"{approval.upstream}.{approval.tool}",
        "argsHash": hash_args(approval.args),
        "via": via,
    }
    ctx.audit.record(
        AuditRecordInput(
            id=new_id("evt"),
            tenantId=approval.tenantId,
            ts=datetime.now(UTC).isoformat(),
            actor=AuditActor(
                agentId="control-plane", userId=decided_by, grantId="-", tokenJti="-"
            ),
            action=AuditAction(
                callId=new_id("call"),
                upstream="control",
                tool=f"approvals.{decision}",
                argsHash=hash_args(payload),
            ),
            decision=AuditDecision(
                effect="allow",
                source="operator",
                reason=f"approvals.{decision} by {decided_by_name} ({decided_by}) via {via}",
            ),
            result=AuditResult(status="executed"),
        )
    )
