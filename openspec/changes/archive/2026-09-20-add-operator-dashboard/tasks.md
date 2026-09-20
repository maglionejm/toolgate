# Tasks: add-operator-dashboard

## 1. Backend
- [x] 1.1 `store.delivery_counts(tenant_id)` accessor (real columns only, no JSON-path SQL; inherited by `PostgresStore` unchanged)
- [x] 1.2 `src/toolgate/server/dashboard.py`: pure `build_dashboard(...)` implementing the design.md contract (clamping, 48-bucket windowing, totals, topTools/budgets ordering, approvals snapshot, operational block, zero-fill edge semantics)
- [x] 1.3 Thin `GET /v1/control/dashboard` handler in `control.py` (`auditor_dep`, `_require_tenant`, store reads + anchor-worker status → `build_dashboard`)
- [x] 1.4 Unit tests for `build_dashboard` (bucketing boundaries incl. `ts == to` clamp, hours clamping, ordering/tiebreaks, empty-tenant zero shapes, control-record exclusion, costUnits/activeAgents math, anchoring enabled/disabled/degraded mapping)
- [x] 1.5 Endpoint tests (auditor vs no-auth gating, unknown-tenant 404 envelope, tenant isolation, camelCase shape, read-only: audit length + rows unchanged after requests)
- [x] 1.6 `delivery_counts` covered in the Postgres parity suite (`tests/test_postgres.py`, DSN-gated)

## 2. Design & Frontend
- [x] 2.1 Designer: complete the `## UI design` section in design.md (layout, tiles, sparkline, bars, operational strip, degraded states) within the existing console visual idiom
- [x] 2.2 Console: Dashboard tab (first tab) in `index.html` + `renderDashboard()` in `app.js` — one `api()` call per render, existing polling cadence, dependency-free vanilla JS/CSS
- [x] 2.3 Console: zero/empty states (fresh tenant), degraded-anchoring indicator, budget bars incl. revoked grants, `styles.css` additions

## 3. QA
- [x] 3.1 Edge tests: hours=1 and hours=168 windows, out-of-range clamps, empty tenant, tenant with only control-plane records, all-denied windows, oldest-pending-age null vs populated
- [x] 3.2 Cross-store parity run (SQLite default suite + `TOOLGATE_TEST_PG_DSN` job) covering the dashboard endpoint
- [x] 3.3 Browser verification: seeded demo data, Dashboard tab renders tiles/series/tools/budgets/operational; verify against the live endpoint response
- [x] 3.4 `uv run ruff check src tests` (unpiped) and full `uv run pytest -q` green

## 4. Docs
- [x] 4.1 `docs/reference/API.md`: `GET /v1/control/dashboard` entry (params, full response shape, edge semantics) matching design.md verbatim
- [x] 4.2 README + console docs: mention the Dashboard tab in the console surface list
- [x] 4.3 OPERATIONS: note the dashboard as the operator-facing surface for degraded anchoring (complements `/healthz` alerting)
- [x] 4.4 Verification: `npx -y @fission-ai/openspec@latest validate --all` passes; docs examples spot-checked against a running server
