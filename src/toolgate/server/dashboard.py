"""Operator dashboard projection (spec: add-operator-dashboard). Every number
here is derived on demand from state the system already maintains — the signed
audit chain, live grant budgets, pending approvals, checkpoints, delivery rows
— rather than from a parallel metrics store, because a counter that disagrees
with the verifiable chain is a trust problem while a slow read is merely a
future optimization problem. Aggregation is pure Python over model lists (one
pass per request, the same cost `/reports` already pays) so the store's SQL
stays portable across SQLite and Postgres with no dialect-specific JSON
aggregation and no new store overrides.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from .context import AppContext

# Fixed bucket count: the payload stays bounded and the sparkline geometry is
# identical for every window. bucketSeconds = hours * 3600 / 48 = hours * 75.
BUCKETS = 48
MIN_HOURS = 1
MAX_HOURS = 168

_STATUS_KEY = {
    "executed": "executed",
    "denied": "denied",
    "pending_approval": "parked",
    "error": "errors",
}
_DELIVERY_STATUSES = ("pending", "delivered", "failed")


def build_dashboard(
    ctx: AppContext, tenant_id: str, hours: int, now: datetime | None = None
) -> dict[str, Any]:
    """Compute the full dashboard payload for one tenant. `now` is injectable
    so windowing and bucketing are deterministic under test."""
    now = now or datetime.now(UTC)
    hours = max(MIN_HOURS, min(MAX_HOURS, hours))
    bucket_seconds = hours * 75
    window_start = now - timedelta(hours=hours)

    totals = {"calls": 0, "executed": 0, "denied": 0, "parked": 0, "errors": 0,
              "costUnits": 0, "activeAgents": 0}
    series = [
        {"start": (window_start + timedelta(seconds=i * bucket_seconds)).isoformat(),
         "executed": 0, "denied": 0, "parked": 0, "errors": 0}
        for i in range(BUCKETS)
    ]
    agents: set[str] = set()
    tools: dict[str, dict[str, int]] = {}

    for record in ctx.store.list_audit(tenant_id):
        # Gate calls only: operator ops-audit records share the chain but are
        # not tenant workload (same exclusion as /reports).
        if record.action.upstream == "control":
            continue
        ts = datetime.fromisoformat(record.ts)
        if not (window_start <= ts < now):
            continue
        key = _STATUS_KEY[record.result.status]
        totals["calls"] += 1
        totals[key] += 1
        if record.result.status == "executed":
            totals["costUnits"] += record.result.costUnits or 0
        agents.add(record.actor.agentId)
        # min-clamp absorbs the ts == to boundary race at the newest bucket.
        index = min(BUCKETS - 1, int((ts - window_start).total_seconds() // bucket_seconds))
        series[index][key] += 1  # type: ignore[operator]
        tool = tools.setdefault(
            f"{record.action.upstream}.{record.action.tool}", {"calls": 0, "denied": 0}
        )
        tool["calls"] += 1
        if record.result.status == "denied":
            tool["denied"] += 1

    totals["activeAgents"] = len(agents)

    top_tools = [
        {"tool": name, "calls": stats["calls"], "denied": stats["denied"]}
        for name, stats in sorted(tools.items(), key=lambda kv: (-kv[1]["calls"], kv[0]))[:10]
    ]

    # Durable state, not windowed: operators need revoked grants visible too.
    budgets = sorted(
        (
            {
                "grantId": g.id,
                "agentId": g.agentId,
                "spentUnits": g.budget.spentUnits,
                "maxUnits": g.budget.maxUnits,
                "status": g.status,
            }
            for g in ctx.store.list_grants(tenant_id)
        ),
        key=lambda b: (-(b["spentUnits"] / b["maxUnits"]), b["grantId"]),  # type: ignore[operator]
    )

    pending = ctx.store.list_approvals(tenant_id, "pending")
    oldest_age: int | None = None
    if pending:
        oldest = min(datetime.fromisoformat(a.requestedAt) for a in pending)
        oldest_age = int((now - oldest).total_seconds())

    # Anchoring is chain-wide (deployment-global), same inputs as /healthz —
    # but always emit all four keys so the client never branches on shape.
    checkpoints = ctx.store.list_checkpoints()
    total = len(checkpoints)
    anchored = sum(1 for c in checkpoints if c.anchor)
    if ctx.anchor_worker is not None:
        status = ctx.anchor_worker.status(total=total, anchored=anchored)
        anchoring = {
            "enabled": bool(status.get("enabled", True)),
            "anchored": status.get("anchored", anchored),
            "total": status.get("total", total),
            "degraded": bool(status.get("degraded", False)),
        }
    else:
        anchoring = {"enabled": False, "anchored": anchored, "total": total, "degraded": False}

    raw_deliveries = ctx.store.delivery_counts(tenant_id)
    deliveries = {status: raw_deliveries.get(status, 0) for status in _DELIVERY_STATUSES}

    return {
        "tenantId": tenant_id,
        "window": {
            "hours": hours,
            "from": window_start.isoformat(),
            "to": now.isoformat(),
            "bucketSeconds": bucket_seconds,
        },
        "totals": totals,
        "series": series,
        "topTools": top_tools,
        "budgets": budgets,
        "approvals": {"pending": len(pending), "oldestPendingAgeSeconds": oldest_age},
        "operational": {
            "anchoring": anchoring,
            "deliveries": deliveries,
            "authFailures": dict(ctx.auth_failure_counts),
        },
    }
