# Operator dashboard: fleet overview in the console (metrics API + UI)

## Why
GitHub issue: #73. Operators have no at-a-glance operational picture of a deployment. Today they stitch it together from `/v1/control/reports` (lifetime rollup, no time dimension), the raw audit table, and `/healthz` (anchoring + auth-failure telemetry, unauthenticated and instance-shaped). Questions like "is anything being denied right now?", "which grant is about to exhaust its budget?", and "are approvals piling up?" require manual cross-referencing. A single tenant-scoped metrics endpoint plus a console Dashboard tab answers them in one screen.

## What Changes
- New read-only, auditor-gated `GET /v1/control/dashboard` endpoint: time-bucketed call series (executed/denied/parked/errors), headline totals, top tools, per-grant budget utilization, approvals snapshot, and an operational block (anchoring, delivery counts, auth failures) — all derived from existing state (audit chain, grants, approvals, checkpoints, deliveries, in-memory failure counters). No new counters, no new write paths.
- A small pure aggregation module `src/toolgate/server/dashboard.py` builds the payload from store reads; the endpoint in `control.py` stays thin.
- One new read-only store accessor: `delivery_counts(tenant_id)` (portable SQL over real columns; works unchanged on SQLite and Postgres).
- Console: new Dashboard tab (first tab) rendering KPI tiles, sparkline series, horizontal-bar top tools, budget bars, and an operational status strip — dependency-free vanilla JS/CSS in the existing console idiom.
- Docs: API reference entry, README + console mention, OPERATIONS pointer for the degraded-anchoring surface.

Non-goals: no historical metrics storage or downsampling beyond the audit chain itself; no per-operator dashboards; no push/streaming updates (the console polls like existing views); no changes to `/v1/control/reports` or `/healthz`.

## Impact
- Affected specs: dashboard (new)
- Affected code: server (`control.py` endpoint, new `dashboard.py`, `store.py` accessor), console (`index.html`, `app.js`, `styles.css`), docs (`docs/reference/API.md`, README, OPERATIONS)
