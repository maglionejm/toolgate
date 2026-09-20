# Design: operator dashboard

## Context

Everything the dashboard shows already exists as state: the signed audit chain (`store.list_audit(tenant_id)` → `AuditRecord{ts, actor{agentId,userId,grantId}, action{upstream,tool}, decision{effect,source}, result{status,latencyMs,costUnits}}`), grants with live budgets (`list_grants`), pending approvals (`list_approvals(tenant_id, "pending")`), checkpoints + `AnchorWorker.status()` (the `/healthz` anchoring block), notification delivery rows, and the in-memory `ctx.auth_failure_counts` telemetry. The dashboard is a pure read-side projection over that state, following the `/v1/control/reports` idiom (auditor-gated, tenant-scoped, derived entirely from verifiable records).

## API contract

This section is normative. Backend and frontend build against it verbatim.

### Endpoint

```
GET /v1/control/dashboard?tenantId=<tnt_...>&hours=<int>
```

- **Auth**: auditor-gated via the existing `require_role` dependency (`dependencies=auditor_dep`); accepts `X-Toolgate-Operator-Key` or the break-glass `X-Toolgate-Admin-Key`, exactly like `GET /v1/control/reports`.
- **`tenantId`** (required, query): validated with `_require_tenant`; an unknown tenant returns the standard 404 envelope `{"error": {"code": "TG_NOT_FOUND", "message": "tenant not found: <id>"}}`.
- **`hours`** (optional, query, integer, default `24`): the lookback window. Out-of-range integers are **clamped** to `[1, 168]` (not rejected); the effective value is echoed in `window.hours`. A non-integer value fails FastAPI validation and returns the standard 400 `TG_VALIDATION` envelope.
- **Method/side effects**: GET only; performs no writes, appends no audit records (parity with `/reports`).

### Response — 200, `application/json`, all fields camelCase (project wire rule)

```jsonc
{
  "tenantId": "tnt_abc",
  "window": {
    "hours": 24,                              // effective (post-clamp) window
    "from": "2026-09-19T14:00:00+00:00",      // to − hours, ISO-8601 UTC
    "to": "2026-09-20T14:00:00+00:00",        // request time, ISO-8601 UTC
    "bucketSeconds": 1800                     // hours * 75 (window / 48)
  },

  "totals": {                                 // whole-window headline numbers
    "calls": 143,                             // int — all gate-call audit records in window
    "executed": 120,                          // int — result.status == "executed"
    "denied": 12,                             // int — result.status == "denied"
    "parked": 8,                              // int — result.status == "pending_approval"
    "errors": 3,                              // int — result.status == "error"
    "costUnits": 456,                         // int — sum of result.costUnits over executed records
    "activeAgents": 4                         // int — distinct actor.agentId in window
  },

  "series": [                                 // ALWAYS exactly 48 buckets, oldest → newest
    {
      "start": "2026-09-19T14:00:00+00:00",   // bucket start, ISO-8601 UTC
      "executed": 5,                          // int
      "denied": 1,                            // int
      "parked": 0,                            // int
      "errors": 0                             // int
    }
    // ... 47 more; empty buckets are present with all-zero counts
  ],

  "topTools": [                               // at most 10 entries
    {
      "tool": "crm.read_contact",             // "{upstream}.{tool}" (reports byTool key format)
      "calls": 40,                            // int — all records for the tool in window
      "denied": 3                             // int — denied records for the tool in window
    }
  ],

  "budgets": [                                // ALL grants of the tenant (durable state, not windowed)
    {
      "grantId": "gnt_1",
      "agentId": "agt_1",
      "spentUnits": 40,                       // int — live budget row (store merges it)
      "maxUnits": 100,                        // int
      "status": "active"                      // "active" | "revoked"
    }
  ],

  "approvals": {
    "pending": 2,                             // int — approvals with status == "pending"
    "oldestPendingAgeSeconds": 341            // int — now − min(requestedAt); null when pending == 0
  },

  "operational": {
    "anchoring": {                            // deployment-global (checkpoints are chain-wide, not per-tenant)
      "enabled": true,                        // bool — anchor worker configured
      "anchored": 3,                          // int — checkpoints carrying anchor evidence
      "total": 4,                             // int — all checkpoints
      "degraded": false                       // bool — AnchorWorker.degraded (consecutive failures)
    },
    "deliveries": {                           // tenant-scoped notification delivery counts, all keys always present
      "pending": 1,                           // int
      "delivered": 10,                        // int
      "failed": 0                             // int
    },
    "authFailures": {                         // deployment-global, in-memory since process start
      "assertion_invalid": 2                  // map of reason class → count; {} when none
    }
  }
}
```

### Semantics

- **Record selection**: gate-call records only — audit records with `action.upstream == "control"` (operator ops-audit) are excluded, exactly as in `/v1/control/reports`. A record is in-window when `from <= ts < to` (`ts` parsed with `datetime.fromisoformat`).
- **Bucketing**: fixed **48 buckets** regardless of window; `bucketSeconds = hours * 3600 / 48` (= `hours * 75`, always an integer for integer hours). Bucket `i` starts at `from + i * bucketSeconds`. A record's index is `min(47, floor((ts − from) / bucketSeconds))` (the min-clamp absorbs the `ts == to` boundary race). Buckets are zero-filled: all 48 are always present, in chronological order.
- **Timestamps**: all ISO-8601 UTC with explicit offset (`datetime.now(UTC).isoformat()` format), matching the rest of the wire surface.
- **`totals`**: computed over the same in-window record set. `costUnits` sums `result.costUnits or 0` over executed records only. `activeAgents` counts distinct `actor.agentId`.
- **`topTools` ordering**: `calls` descending, then `tool` ascending (deterministic tiebreak); truncated to 10.
- **`budgets` ordering**: utilization (`spentUnits / maxUnits`) descending, then `grantId` ascending. Includes revoked grants (operators need to see them); not filtered by window.
- **`approvals`**: from `list_approvals(tenantId, status="pending")`; `oldestPendingAgeSeconds` is `now − min(requestedAt)` rounded down to whole seconds, `null` when there are no pending approvals.
- **`operational.anchoring`**: same inputs as the `/healthz` anchoring block — `ctx.anchor_worker.status(total=len(checkpoints), anchored=sum(1 for c in checkpoints if c.anchor))` when a worker exists, mapped onto the four camelCase fields above; when no worker is configured: `{"enabled": false, "anchored": <anchored count>, "total": <checkpoint count>, "degraded": false}`. Checkpoints and anchoring are chain-wide (deployment-global) and identical for every tenant; that is acceptable — the operational block answers "is this deployment healthy", not "is this tenant healthy".
- **`operational.deliveries`**: from the new store accessor (below); the three status keys are always present, zero-filled.
- **`operational.authFailures`**: `dict(ctx.auth_failure_counts)` — same map `/healthz` exposes; keys are reason classes; deployment-global and reset on process restart. Empty object when no failures.

### Edge semantics

- **Empty tenant** (exists, no activity): 200 with zeroed `totals`, 48 all-zero `series` buckets, `topTools: []`, `budgets: []`, `approvals: {"pending": 0, "oldestPendingAgeSeconds": null}`, zero-filled `deliveries` — never an error, never missing keys.
- **Unknown tenant**: 404 `TG_NOT_FOUND` envelope (see above), before any aggregation.
- **Wire-format impact**: response fields are camelCase throughout (protocol rule). The endpoint reads audit records but never re-serializes them into storage — audit record hash stability is untouched.

## Computation placement

- **`src/toolgate/server/dashboard.py`** (new): an HTTP-free module exposing one function:

  ```python
  def build_dashboard(
      ctx: AppContext,
      tenant_id: str,
      hours: int,                      # raw request value; clamping lives here (single home)
      now: datetime | None = None,     # injected for deterministic tests; defaults to utcnow
  ) -> dict[str, Any]: ...
  ```

  `build_dashboard` owns clamping, windowing, bucketing, ordering, and shape — it is the single source of truth for the contract. It takes the app context and performs the store reads itself (`list_audit`, `list_grants`, `list_approvals(..., "pending")`, `list_checkpoints`, `delivery_counts`, plus `ctx.anchor_worker.status(...)` when a worker exists and `ctx.auth_failure_counts`), so the HTTP handler stays a one-liner and unit tests exercise the exact read path the endpoint uses; determinism comes from the injectable `now`. (An earlier draft passed pre-fetched model lists instead; the context-taking form was chosen so the endpoint and the tests cannot drift on *which* reads feed the payload.)
- **`control.py`**: a thin `@router.get("/dashboard", dependencies=auditor_dep)` handler that runs `_require_tenant` and returns `build_dashboard(ctx, tenantId, hours)`.

## New store accessor

One read-only method on `Store` (inherited unchanged by `PostgresStore`):

```python
def delivery_counts(self, tenant_id: str) -> dict[str, int]:
    """Notification delivery counts by status for a tenant (dashboard read)."""
    rows = self.db.execute(
        "SELECT status, COUNT(*) FROM deliveries WHERE tenant_id = ? GROUP BY status",
        (tenant_id,),
    ).fetchall()
    return {row[0]: row[1] for row in rows}
```

Portability: it touches only real columns (`status`, `tenant_id`) — no `json_extract`, so no Postgres override is needed; the qmark→`%s` facade handles the placeholder. Every other input to the dashboard uses existing accessors with pure-Python aggregation.

## UI design

The dashboard is a new tab labelled **Dashboard**, placed **first** in `#tabs` and made the **default active view**: the tab button carries `class="active"`, `#view-dashboard` is the only section without `hidden` (add `hidden` to `#view-approvals`), and `app.js` changes `let view = "approvals"` to `let view = "dashboard"`. Operators land on it after sign-in. Everything below uses only fields the API contract provides; all user-sourced strings (tool names, grant/agent ids, error messages) pass through the existing `esc()`.

### Layout

Top to bottom inside `#view-dashboard` (tenant selector stays above, shared with all views):

```
┌ panel-label: operational status ──────────────── updated 14:02:11 ┐
│ [ANCHORING 3/4] [DELIVERIES 10 ok · 1 pending] [AUTH FAILURES 0]  │  (a) status strip
│ [APPROVALS 2 pending · oldest 5m 41s]                             │
├ panel-label: activity · window ───────────────── [1h][24h][7d] ───┤
│ ┌calls──┐┌denied─┐┌parked─┐┌errors─┐┌cost units┐┌active agents┐   │  (b) KPI tiles
│ │  143  ││  12   ││   8   ││   3   ││   456    ││      4      │   │
│ └───────┘└───────┘└───────┘└───────┘└──────────┘└─────────────┘   │
│ executed   120  ▁▂▄▆▄▂▁▂▃▅▆▅▃▂▁▁▂▄▅▆▄▂▁  (48-bucket sparklines,   │  (c) activity
│ denied      12  ▁▁▁▂▁▁▁▁▁▃▁▁▁▁▁▁▁▁▁▁▁▁▁   one row per status)     │
│ parked       8  ▁▁▂▁▁▁▁▁▁▁▁▁▂▁▁▁▁▁▁▁▁▁▁                           │
│ errors       3  ▁▁▁▁▁▁▁▁▁▂▁▁▁▁▁▁▁▁▁▁▁▁▁                           │
├ top tools · calls ────────────┬ budget utilization · all grants ──┤
│ crm.read_contact   40 · 3 den │ gnt_1 · agt_1     40/100 · 40%    │  (d) two-column bars
│ ███████████▓──────            │ ████████──────────                │
│ mail.send          22         │ gnt_2 · agt_2   95/100 · 95% ·    │
│ ███████──────────             │ █████████████████─   NEAR LIMIT   │
└───────────────────────────────┴───────────────────────────────────┘
```

**(a) Status strip** — four cells rendered as existing `.badge mono` chips (state → variant in *States* below). Order: anchoring, deliveries, auth failures, pending approvals. The approvals chip is a `<button>` that activates the Approvals tab (dispatch a click on `#tabs button[data-view="approvals"]`). A right-aligned `hint mono` shows `updated HH:MM:SS` from `window.to`.

**(b) KPI tiles** — six, reusing `.tiles`/`.tile` verbatim: **calls** (headline volume — is the tenant alive), **denied** (policy friction — the number an operator investigates), **parked** (human-queue pressure — pairs with the approvals chip), **errors** (upstream health — distinct failure mode from denial), **cost units** (budget burn across the tenant), **active agents** (who is generating the load). `executed` gets no tile: it is derivable (`calls − denied − parked − errors`) and is already the dominant sparkline. On `denied`/`errors` tiles, the value `<b>` additionally gets class `fx-deny` when > 0 (same semantic-color idiom as the audit table; the label word still carries the meaning).

**(c) Activity chart** — **small-multiple sparklines**, one row per status (`executed`, `denied`, `parked`, `errors`), each an inline SVG area+line over the 48 buckets. *One-line justification: executed typically dwarfs denied/parked, so per-row y-scales keep low-volume anomaly spikes legible instead of crushing them under a stacked area — and rows are label-distinguished, never color-only.* Window selector: a mini segmented control `[1h][24h][7d]` mapping to `hours=1/24/168`, default **24h**; clicking re-fetches with the chosen `hours` and updates the `panel-label` window text from the echoed `window.hours`.

**(d) Two-column** — CSS grid, `1fr 1fr` (single column ≤ 840 px). Left: `topTools` as horizontal bar rows (never a pie), each bar showing total calls with a denied segment. Right: `budgets` as utilization bar rows, one per grant, in the contract's order (utilization desc).

**(e) Refresh** — poll every **30 s**, not the approvals 4 s: the dashboard aggregates a whole window server-side (full-chain scan per request), and approval urgency is already served by the Approvals tab's own 4 s poll plus the strip chip that links there. Implementation reuses the existing `render()`/`pollTimer` pattern: the dashboard branch does `await renderDashboard(); pollTimer = setInterval(renderDashboard, 30000);`. Tenant change and window-selector clicks re-fetch immediately (they run through `render()`/`renderDashboard()` as today).

### DOM sketch (`index.html`)

Tabs (Dashboard first + active; `hidden` moves to approvals):

```html
<div class="tabs" id="tabs">
  <button data-view="dashboard" class="active">Dashboard</button>
  <button data-view="approvals">Approvals</button>
  <!-- Audit / Grants / Simulator / Reports / Channels / Connections unchanged -->
</div>
```

New section (static skeleton; all lists filled by JS):

```html
<section class="view" id="view-dashboard">
  <div class="row-between">
    <p class="panel-label">operational status · deployment + tenant</p>
    <span class="hint mono" id="dash-updated"></span>
  </div>
  <div class="status-strip" id="dash-strip"></div>

  <div class="row-between">
    <p class="panel-label">activity · last <span id="dash-window-label">24h</span></p>
    <div class="seg mono" id="dash-window">
      <button data-hours="1">1h</button>
      <button data-hours="24" class="active">24h</button>
      <button data-hours="168">7d</button>
    </div>
  </div>
  <div class="tiles" id="dash-tiles"></div>
  <div class="sparks" id="dash-sparks"></div>

  <div class="dash-cols">
    <div>
      <p class="panel-label">top tools · calls in window</p>
      <div class="bars" id="dash-tools"></div>
    </div>
    <div>
      <p class="panel-label">budget utilization · all grants</p>
      <div class="bars" id="dash-budgets"></div>
    </div>
  </div>
</section>
```

JS-generated row templates:

```html
<!-- one per status, inside #dash-sparks -->
<div class="spark-row">
  <span class="spark-label mono">executed</span>
  <span class="spark-total mono">120</span>
  <svg class="spark s-executed" viewBox="0 0 480 60" preserveAspectRatio="none">
    <path class="spark-fill" d="M5,56 L5,32 L15,28 … L475,50 L475,56 Z"/>
    <polyline class="spark-line" points="5,32 15,28 … 475,50"/>
  </svg>
</div>

<!-- one per tool / grant, inside #dash-tools / #dash-budgets -->
<div class="bar-row mono">
  <span class="bar-label">crm.read_contact</span>
  <span class="bar-val">40 · 3 denied</span>
  <div class="bar-track"><div class="bar-fill" style="width:62%"><div class="bar-seg-denied" style="width:8%"></div></div></div>
</div>
```

### CSS plan

**Reused verbatim:** `.view`, `.panel-label`, `.row-between`, `.hint`, `.mono`, `.tiles`/`.tile`, `.badge` (+ `.ok`/`.bad`), `.fx-deny`, `.empty` (the `cards .empty` look — generalize its selector to `.empty` so it applies outside `.cards`), tab styles.

**New rules** (append to `styles.css`; tokens only, no new colors beyond `:root`):

```css
/* status strip */
.status-strip { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 22px; }
.status-strip .badge { font-family: var(--mono); background: var(--panel); }
.badge.warn { color: var(--approve); border-color: var(--approve); }
button.badge { cursor: pointer; }

/* window segmented control (miniature of .tabs) */
.seg { display: flex; border: 1px solid var(--line); }
.seg button { font-family: var(--mono); font-size: 11px; background: none; color: var(--muted);
  border: 0; padding: 5px 10px; cursor: pointer; }
.seg button.active { background: var(--accent); color: #0d1105; font-weight: 600; }

/* sparklines */
.sparks { display: grid; gap: 10px; margin-bottom: 24px; }
.spark-row { display: grid; grid-template-columns: 84px 56px 1fr; gap: 12px; align-items: center; }
.spark-label { font-size: 11px; text-transform: uppercase; letter-spacing: .1em; color: var(--faint); }
.spark-total { font-size: 13px; text-align: right; color: var(--text); }
.spark { width: 100%; height: 44px; display: block; background: var(--raise); border: 1px solid var(--line); }
.spark .spark-fill { fill: currentColor; opacity: .16; }
.spark .spark-line { fill: none; stroke: currentColor; stroke-width: 1.5; vector-effect: non-scaling-stroke; }
.s-executed { color: var(--allow); }
.s-denied   { color: var(--deny); }
.s-parked   { color: var(--approve); }
.s-errors   { color: var(--muted); }

/* two-column + bar rows */
.dash-cols { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }
@media (max-width: 840px) { .dash-cols { grid-template-columns: 1fr; } }
.bars { display: grid; gap: 10px; align-content: start; }
.bar-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 4px 12px; font-size: 12px; }
.bar-label { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-val { color: var(--faint); text-align: right; }
.bar-track { grid-column: 1 / -1; height: 8px; background: var(--raise); border: 1px solid var(--line); }
.bar-fill { height: 100%; background: var(--accent-dim); display: flex; }
.bar-fill .bar-seg-denied { height: 100%; background: var(--deny); }
.bar-fill.warn { background: var(--approve); }
.bar-fill.over { background: var(--deny); }
.bar-row.revoked { opacity: .55; }
```

### Rendering spec

**Sparkline** — one pure function `spark(vals, cls)` returning an SVG string, called four times (~30 lines total):

- Geometry: `viewBox="0 0 480 60"`, `preserveAspectRatio="none"`, CSS height 44 px (stretches; `vector-effect: non-scaling-stroke` keeps the line 1.5 px).
- X: 48 buckets × 10 units; point `i` at bucket center `x(i) = i * 10 + 5` → 5, 15, …, 475.
- Y: `max = Math.max(1, ...vals)`; `y(v) = 56 − (v / max) * 50` (baseline y = 56, 6-unit headroom), rounded to 1 decimal. **All-zeros case:** the `max(1, …)` clamp makes every point `y = 56` — a flat line on the baseline, no division by zero, no special path.
- Line: `<polyline points="x0,y0 x1,y1 … x47,y47">`. Area: `<path d="M5,56 L x0,y0 … L x47,y47 L475,56 Z">` (separate elements so the closing edges are fill-only, never stroked).
- `spark-total` is the window total for that status from `totals` (`executed`/`denied`/`parked`/`errors`).

**Top-tools bars** — `maxCalls = Math.max(1, topTools[0]?.calls ?? 0)` (list arrives sorted desc). Fill width `= Math.round(t.calls / maxCalls * 100)`%. Denied segment nested inside the fill, width `= Math.round(t.denied / t.calls * 100)`% *of the fill* (0 when `calls` is 0). Value text: `` `${calls} · ${denied} denied` `` when `denied > 0`, else just the call count.

**Budget bars** — `util = b.maxUnits > 0 ? b.spentUnits / b.maxUnits : 0`; `pct = Math.round(util * 100)`; fill width `= Math.min(100, pct)`%. Label: `` `${grantId} · ${agentId}` ``; value: `` `${spentUnits}/${maxUnits} · ${pct}%` ``. **Over-80 % treatment:** `util >= 0.8` → fill gets `.warn` (amber) and value appends ` · NEAR LIMIT`; `util >= 1` → fill gets `.over` (deny red) and appends ` · EXHAUSTED` instead — the word, not the color, is the signal. Revoked grants: row gets `.revoked` (dimmed) and value appends ` · revoked`.

**Number formatting** — tile values and totals via `n.toLocaleString("en-US")` (mono renders tabular). Ages from `oldestPendingAgeSeconds`: `fmtAge(s)` → `null` ⇒ `"—"`; `s ≥ 3600` ⇒ `` `${h}h ${m}m` ``; `s ≥ 60` ⇒ `` `${m}m ${r}s` ``; else `` `${s}s` ``. Timestamps (updated-at) via the existing `iso.slice(11, 19)` idiom.

### States

- **Loading** (first paint, before fetch resolves): `#dash-strip` shows a single neutral `<span class="badge mono">loading…</span>`; tiles/sparks/bars stay empty. No spinners.
- **Empty tenant** (`totals.calls === 0`; contract guarantees zeroed shape): tiles show `0`, all four sparklines render flat on the baseline, and an `.empty` line under `#dash-sparks` reads `— no gate calls in this window —`. `#dash-tools` empty ⇒ `.empty` `no tool calls in window`; `#dash-budgets` empty ⇒ `.empty` `no grants — toolgate grants create`. The status strip still renders (operational block is always present).
- **Fetch error**: `#dash-strip` is replaced with `<span class="badge bad mono">FETCH FAILED · ${code}: ${message}</span>` (login-err idiom); previously rendered tiles/charts are left in place (stale data an operator is reading is better than a wipe), and the 30 s poll keeps retrying.
- **Degraded operational** (word-prefixed, never color-only):
  - `anchoring.degraded: true` ⇒ `badge bad` reading `ANCHORING DEGRADED · 3/4 anchored`. Healthy ⇒ `badge ok` `ANCHORING 3/4`. `enabled: false` ⇒ neutral `badge` `ANCHORING OFF · 3/4 anchored` (configured-off is a choice, not a fault).
  - `deliveries.failed > 0` ⇒ `badge bad` `DELIVERIES 2 FAILED · 10 delivered · 1 pending`; else `badge ok` `DELIVERIES 10 delivered · 1 pending`.
  - `authFailures`: sum the map's counts. 0 ⇒ neutral `badge` `AUTH FAILURES 0`; > 0 ⇒ `badge warn` `AUTH FAILURES 3 · assertion_invalid 2 · pop_invalid 1` (list every reason class; deployment-global since process start).
  - `approvals.pending > 0` ⇒ `badge warn` `APPROVALS 2 pending · oldest 5m 41s` (clickable → Approvals tab); 0 ⇒ neutral `APPROVALS none pending`.

## Decisions

- **Derive from the audit chain; add no counters or write paths.** The chain is already the verifiable system of record (`/reports` set the precedent); a parallel metrics store would drift from it, add write amplification on the gate hot path, and create a second thing to migrate. A dashboard read that is slow at huge scale is a future optimization problem; a metrics table that disagrees with the signed chain is a trust problem.
- **Pure-Python aggregation over model lists.** The store's SQL stays portable across SQLite and Postgres precisely because it avoids dialect-specific JSON aggregation (CLAUDE.md rule: new `json_extract` SQL requires a PG override). At current scale (`/reports` already iterates the full tenant chain per request) a single pass over `list_audit(tenant_id)` is fine, keeps `build_dashboard` testable without a database, and needs zero store overrides. The one new SQL query (`delivery_counts`) uses only real columns for the same reason.
- **Fixed 48 buckets, `bucketSeconds = window/48`.** A constant bucket count keeps the payload size bounded and the sparkline geometry identical for every window (the frontend always plots 48 points — no adaptive-axis logic). 48 gives 30-minute resolution at the default 24 h window and stays integral in seconds for all integer `hours` (hours × 75). Zero-filling server-side means the client never interpolates gaps.
- **`hours` clamps instead of erroring.** The parameter tunes a view; an out-of-range value has an obvious best interpretation, and the echoed `window.hours` keeps the client honest.
