# dashboard Specification

## Purpose
Give operators a single, tenant-scoped operational picture of a Toolgate deployment — is anything being denied right now, which grant is about to exhaust its budget, are approvals piling up, is anchoring healthy — without stitching it together from `/reports`, the raw audit table, and `/healthz`. The capability is a read-only projection over state the system already keeps (signed audit chain, live grant budgets, pending approvals, checkpoints, delivery rows, in-memory auth-failure telemetry): no parallel metrics store, no new write paths, identical behaviour on SQLite and Postgres. Surfaces: `GET /v1/control/dashboard` (documented in `docs/reference/API.md`; normative contract in the archived change's design.md) and the console's Dashboard tab.

## Requirements

### Requirement: Tenant-scoped, auditor-gated metrics endpoint
The control plane SHALL expose `GET /v1/control/dashboard` gated at auditor level via the existing role dependency, requiring a `tenantId` query parameter validated against the tenant registry (unknown tenant → the standard 404 `TG_NOT_FOUND` error envelope) and accepting an optional integer `hours` window (default 24, clamped to 1–168). All response fields SHALL be camelCase (wire-format rule); the response SHALL match the contract in this change's design.md exactly.

#### Scenario: Auditor fetches the dashboard
- **WHEN** an operator with the auditor role requests `/v1/control/dashboard?tenantId=tnt_x` for an existing tenant
- **THEN** the response is 200 with `window`, `totals`, `series`, `topTools`, `budgets`, `approvals`, and `operational` blocks scoped to that tenant's records

#### Scenario: Unknown tenant
- **WHEN** the dashboard is requested for a tenantId that does not exist
- **THEN** the response is the standard 404 envelope with code `TG_NOT_FOUND` and no aggregation is performed

### Requirement: Zero-filled fixed-bucket windowing
The dashboard SHALL always return exactly 48 chronologically ordered time buckets covering the effective window (`bucketSeconds = hours * 3600 / 48`), zero-filling buckets with no activity, and SHALL compute headline totals (calls, executed, denied, parked, errors, costUnits, activeAgents) over the same in-window gate-call records, excluding control-plane ops-audit records. An existing tenant with no activity SHALL receive zeroed shapes (all-zero buckets, empty `topTools` and `budgets` arrays, `pending: 0` with a null oldest-pending age), never an error or missing keys.

#### Scenario: Empty tenant
- **WHEN** the dashboard is requested for a tenant with no audit records, grants, or approvals
- **THEN** the response is 200 with 48 all-zero buckets, zeroed totals, empty arrays, and null `oldestPendingAgeSeconds`

#### Scenario: Out-of-range window
- **WHEN** the dashboard is requested with `hours=9999`
- **THEN** the window is clamped to 168 hours and `window.hours` echoes 168

### Requirement: Operational status surfacing
The dashboard SHALL include an `operational` block surfacing anchoring state (enabled/anchored/total/degraded, from checkpoints plus the anchor worker when configured), tenant notification delivery counts by status (pending/delivered/failed, always all three keys), and the deployment's auth-failure counters by reason class — so a degraded deployment is visible without consulting `/healthz`.

#### Scenario: Degraded anchoring is visible
- **WHEN** the anchor worker has accumulated consecutive checkpoint-anchoring failures past its degradation threshold
- **THEN** the dashboard's `operational.anchoring.degraded` is true while `anchored`/`total` show the coverage shortfall

### Requirement: Console dashboard view
The operator console SHALL render a Dashboard view for the selected tenant from the single dashboard endpoint response: headline KPI tiles, the 48-bucket call series, top tools with denial counts, per-grant budget utilization, and the operational status (including a visible degraded-anchoring indicator) — implemented dependency-free in the existing console idiom and refreshed on the console's existing polling cadence.

#### Scenario: Operator opens the Dashboard tab
- **WHEN** a signed-in operator selects the Dashboard tab with a tenant chosen
- **THEN** the console issues exactly one request to `/v1/control/dashboard` for that tenant and renders tiles, series, top tools, budgets, and operational status from that response

### Requirement: Read-only guarantee
The dashboard SHALL introduce no new write paths: serving it SHALL NOT insert, update, or delete any store row, SHALL NOT append audit records, and SHALL NOT add counters or tables — every value is derived from existing state (audit chain, grants, approvals, checkpoints, deliveries, in-memory failure telemetry). Audit records are read, never re-serialized into storage, so audit-record hash stability is unaffected.

#### Scenario: Serving the dashboard leaves state untouched
- **WHEN** the dashboard is requested repeatedly for a tenant
- **THEN** the audit chain length, all entity rows, and all delivery rows are byte-identical before and after the requests

### Requirement: Store backend parity
Dashboard aggregation SHALL behave identically on the SQLite and Postgres stores: computation is pure Python over existing model-list accessors, and any new store SQL (the `delivery_counts` accessor) SHALL use only real columns (no `json_extract`/JSON-path operators), so `PostgresStore` inherits it unchanged through the placeholder facade.

#### Scenario: Same counts on both backends
- **WHEN** identical delivery rows exist in a SQLite store and a Postgres store
- **THEN** `delivery_counts(tenantId)` returns the same status→count mapping on both, with no Postgres-specific override
