/* Toolgate console. The key never leaves sessionStorage; every request carries
   the right header for its kind (operator vs break-glass admin). */
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function authHeader() {
  const key = sessionStorage.getItem("tgKey") || "";
  return key.startsWith("opk_")
    ? { "x-toolgate-operator-key": key }
    : { "x-toolgate-admin-key": key };
}

async function api(path, body, method) {
  const res = await fetch(path, {
    method: method || (body === undefined ? "GET" : "POST"),
    headers: { ...authHeader(), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(json.error?.message || res.status), { code: json.error?.code });
  return json;
}

/* ---------- login ---------- */

async function connect(key) {
  sessionStorage.setItem("tgKey", key);
  await api("/v1/control/tenants"); // auditor-level probe
  $("login").hidden = true;
  $("app").hidden = false;
  $("logout").hidden = false;
  $("who").textContent = key.startsWith("opk_") ? "operator session" : "break-glass session";
  await loadTenants();
  render();
}

$("login-btn").addEventListener("click", async () => {
  try {
    await connect($("key-input").value.trim());
  } catch (err) {
    sessionStorage.removeItem("tgKey");
    $("login-err").textContent = `${err.code || "error"}: ${err.message}`;
  }
});
$("logout").addEventListener("click", () => { sessionStorage.removeItem("tgKey"); location.reload(); });

/* ---------- tenant + tabs ---------- */

let view = "dashboard";
let pollTimer = null;
let dashHours = 24;

async function loadTenants() {
  const tenants = await api("/v1/control/tenants");
  $("tenant").innerHTML = tenants
    .map((t) => `<option value="${esc(t.id)}">${esc(t.name)} (${esc(t.id)})</option>`)
    .join("");
}

$("tenant").addEventListener("change", render);
$("tabs").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-view]");
  if (!btn) return;
  view = btn.dataset.view;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b === btn));
  document.querySelectorAll(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  render();
});

function tenantId() { return $("tenant").value; }

async function render() {
  clearInterval(pollTimer);
  if (view === "dashboard") {
    await renderDashboard();
    pollTimer = setInterval(renderDashboard, 30000);
  } else if (view === "approvals") {
    await renderApprovals();
    pollTimer = setInterval(renderApprovals, 4000);
  } else if (view === "audit") await renderAudit();
  else if (view === "grants") await renderGrants();
  else if (view === "simulator") await loadPolicies();
  else if (view === "reports") await renderReports();
  else if (view === "channels") await renderChannels();
  else if (view === "connections") await renderConnections();
}

/* ---------- dashboard ---------- */

const fmtNum = (n) => n.toLocaleString("en-US");

function fmtAge(s) {
  if (s === null || s === undefined) return "—";
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  if (s >= 60) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${s}s`;
}

/* Inline SVG sparkline over 48 buckets: viewBox 0 0 480 60, point i at bucket
   center x = i*10+5, y = 56 - (v/max)*50 with max clamped to 1 (all-zeros ⇒
   flat baseline, no division by zero). Area path and line are separate so the
   closing edges are fill-only, never stroked. */
function spark(vals, cls) {
  const max = Math.max(1, ...vals);
  const pts = vals.map((v, i) => `${i * 10 + 5},${Math.round((56 - (v / max) * 50) * 10) / 10}`);
  return `<svg class="spark ${cls}" viewBox="0 0 480 60" preserveAspectRatio="none">
    <path class="spark-fill" d="M5,56 L${pts.join(" L")} L475,56 Z"/>
    <polyline class="spark-line" points="${pts.join(" ")}"/>
  </svg>`;
}

function dashStrip(d) {
  const a = d.operational.anchoring;
  const anchor = !a.enabled
    ? `<span class="badge mono">ANCHORING OFF · ${a.anchored}/${a.total} anchored</span>`
    : a.degraded
      ? `<span class="badge bad mono">ANCHORING DEGRADED · ${a.anchored}/${a.total} anchored</span>`
      : `<span class="badge ok mono">ANCHORING ${a.anchored}/${a.total}</span>`;
  const dl = d.operational.deliveries;
  const deliveries = dl.failed > 0
    ? `<span class="badge bad mono">DELIVERIES ${dl.failed} FAILED · ${dl.delivered} delivered · ${dl.pending} pending</span>`
    : `<span class="badge ok mono">DELIVERIES ${dl.delivered} delivered · ${dl.pending} pending</span>`;
  const reasons = Object.entries(d.operational.authFailures).sort(([x], [y]) => (x < y ? -1 : 1));
  const authTotal = reasons.reduce((sum, [, n]) => sum + n, 0);
  const auth = authTotal > 0
    ? `<span class="badge warn mono">AUTH FAILURES ${authTotal} · ${reasons.map(([k, n]) => `${esc(k)} ${n}`).join(" · ")}</span>`
    : `<span class="badge mono">AUTH FAILURES 0</span>`;
  const ap = d.approvals;
  const approvals = ap.pending > 0
    ? `<button class="badge warn mono" data-goto="approvals">APPROVALS ${ap.pending} pending · oldest ${esc(fmtAge(ap.oldestPendingAgeSeconds))}</button>`
    : `<button class="badge mono" data-goto="approvals">APPROVALS none pending</button>`;
  return anchor + deliveries + auth + approvals;
}

async function renderDashboard() {
  if (!tenantId()) return;
  const strip = $("dash-strip");
  if (!strip.innerHTML) strip.innerHTML = `<span class="badge mono">loading…</span>`;
  let d;
  try {
    d = await api(`/v1/control/dashboard?tenantId=${tenantId()}&hours=${dashHours}`);
  } catch (err) {
    // Stale tiles/charts an operator is reading beat a wipe; the poll retries.
    strip.innerHTML = `<span class="badge bad mono">FETCH FAILED · ${esc(err.code || "error")}: ${esc(err.message)}</span>`;
    return;
  }

  strip.innerHTML = dashStrip(d);
  $("dash-updated").textContent = `updated ${d.window.to.slice(11, 19)}`;
  $("dash-window-label").textContent = d.window.hours === 168 ? "7d" : `${d.window.hours}h`;

  const t = d.totals;
  $("dash-tiles").innerHTML = [
    ["calls", t.calls, ""],
    ["denied", t.denied, t.denied > 0 ? "fx-deny" : ""],
    ["parked", t.parked, ""],
    ["errors", t.errors, t.errors > 0 ? "fx-deny" : ""],
    ["cost units", t.costUnits, ""],
    ["active agents", t.activeAgents, ""],
  ]
    .map(([k, v, cls]) => `<div class="tile"><b${cls ? ` class="${cls}"` : ""}>${fmtNum(v)}</b><span>${k}</span></div>`)
    .join("");

  $("dash-sparks").innerHTML = ["executed", "denied", "parked", "errors"]
    .map(
      (k) => `<div class="spark-row">
        <span class="spark-label mono">${k}</span>
        <span class="spark-total mono">${fmtNum(t[k])}</span>
        ${spark(d.series.map((b) => b[k]), `s-${k}`)}
      </div>`
    )
    .join("") + (t.calls === 0 ? `<p class="empty">— no gate calls in this window —</p>` : "");

  const maxCalls = Math.max(1, d.topTools[0]?.calls ?? 0);
  $("dash-tools").innerHTML = d.topTools
    .map((x) => {
      const fill = Math.round((x.calls / maxCalls) * 100);
      const den = x.calls > 0 ? Math.round((x.denied / x.calls) * 100) : 0;
      return `<div class="bar-row mono">
        <span class="bar-label">${esc(x.tool)}</span>
        <span class="bar-val">${x.denied > 0 ? `${x.calls} · ${x.denied} denied` : x.calls}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${fill}%"><div class="bar-seg-denied" style="width:${den}%"></div></div></div>
      </div>`;
    })
    .join("") || `<p class="empty">no tool calls in window</p>`;

  $("dash-budgets").innerHTML = d.budgets
    .map((b) => {
      const util = b.maxUnits > 0 ? b.spentUnits / b.maxUnits : 0;
      const pct = Math.round(util * 100);
      let fillCls = "";
      let val = `${b.spentUnits}/${b.maxUnits} · ${pct}%`;
      if (util >= 1) { fillCls = " over"; val += " · EXHAUSTED"; }
      else if (util >= 0.8) { fillCls = " warn"; val += " · NEAR LIMIT"; }
      const revoked = b.status === "revoked";
      if (revoked) val += " · revoked";
      return `<div class="bar-row mono${revoked ? " revoked" : ""}">
        <span class="bar-label">${esc(b.grantId)} · ${esc(b.agentId)}</span>
        <span class="bar-val">${val}</span>
        <div class="bar-track"><div class="bar-fill${fillCls}" style="width:${Math.min(100, pct)}%"></div></div>
      </div>`;
    })
    .join("") || `<p class="empty">no grants — toolgate grants create</p>`;
}

$("dash-window").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-hours]");
  if (!btn) return;
  dashHours = Number(btn.dataset.hours);
  document.querySelectorAll("#dash-window button").forEach((b) => b.classList.toggle("active", b === btn));
  render(); // immediate re-fetch; re-arms the 30 s poll
});

$("dash-strip").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-goto]");
  if (!btn) return;
  // Same code path as clicking the tab button, so tab state stays consistent.
  document.querySelector(`#tabs button[data-view="${btn.dataset.goto}"]`)?.click();
});

/* ---------- approvals inbox ---------- */

async function renderApprovals() {
  if (!tenantId()) return;
  const pending = await api(`/v1/control/approvals?tenantId=${tenantId()}&status=pending`);
  const wrap = $("approvals-list");
  if (!pending.length) {
    wrap.innerHTML = `<p class="empty">— inbox clear: no pending approvals —</p>`;
    return;
  }
  wrap.innerHTML = pending
    .map(
      (a) => `<div class="card" data-id="${esc(a.id)}">
        <p class="c-head"><b>${esc(a.upstream)}.${esc(a.tool)}</b> · ${esc(a.id)}</p>
        <p class="c-meta">agent ${esc(a.agentId)} · for ${esc(a.userId)} · expires ${esc(a.expiresAt.slice(11, 19))}</p>
        <pre>${esc(JSON.stringify(a.args, null, 2))}</pre>
        <p class="c-meta mono" data-deliveries>notifications: …</p>
        <button class="btn btn-primary btn-sm" data-act="approve">Approve exactly this</button>
        <button class="btn btn-deny btn-sm" data-act="deny">Deny</button>
      </div>`
    )
    .join("");
  // Delivery status per card: which channels the parked approval reached.
  await Promise.all(
    pending.map(async (a) => {
      const slot = wrap.querySelector(`.card[data-id="${CSS.escape(a.id)}"] [data-deliveries]`);
      if (!slot) return;
      try {
        const rows = await api(`/v1/control/approvals/${a.id}/deliveries`);
        slot.textContent = rows.length
          ? "notifications: " + rows.map((d) => `${d.channelType} ${d.status}${d.attempts > 1 ? ` (x${d.attempts})` : ""}`).join(" · ")
          : "notifications: no channels configured";
      } catch { slot.textContent = "notifications: unavailable"; }
    })
  );
}

$("approvals-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const id = btn.closest(".card").dataset.id;
  btn.disabled = true;
  await api(`/v1/control/approvals/${id}/decide`, { decision: btn.dataset.act });
  await renderApprovals();
});

/* ---------- audit explorer ---------- */

async function renderAudit() {
  const badge = $("chain-badge");
  badge.className = "badge mono";
  badge.textContent = "verifying…";
  const [records, verify] = await Promise.all([
    api(`/v1/control/audit?tenantId=${tenantId()}`),
    api("/v1/control/audit/verify"),
  ]);
  const ok = verify.valid && verify.checkpoints_valid === verify.checkpoints_total;
  badge.classList.add(ok ? "ok" : "bad");
  badge.textContent = ok
    ? `chain verified · ${verify.length} records · ${verify.checkpoints_total} checkpoints`
    : `BROKEN at seq ${verify.broken_at_seq ?? "?"}`;
  $("audit-table").querySelector("tbody").innerHTML = records
    .slice(-200)
    .reverse()
    .map(
      (r) => `<tr>
        <td>${r.seq}</td><td>${esc(r.ts.slice(11, 19))}</td>
        <td>${esc(r.actor.userId)}</td>
        <td>${esc(r.action.upstream)}.${esc(r.action.tool)}</td>
        <td class="fx-${esc(r.decision.effect)}">${esc(r.decision.effect)} (${esc(r.decision.source)})</td>
        <td>${esc(r.result.status)}</td>
      </tr>`
    )
    .join("");
}

/* ---------- grants ---------- */

function budgetBar(b) {
  const width = 12;
  const used = b.maxUnits ? Math.round((width * b.spentUnits) / b.maxUnits) : 0;
  return `[${"#".repeat(used)}${"-".repeat(width - used)}] ${b.spentUnits}/${b.maxUnits}`;
}

async function renderGrants() {
  const grants = await api(`/v1/control/grants?tenantId=${tenantId()}`);
  $("grants-table").querySelector("tbody").innerHTML = grants
    .map(
      (g) => `<tr>
        <td>${esc(g.id)}</td><td>${esc(g.agentId)}</td>
        <td>${esc(budgetBar(g.budget))}</td>
        <td class="${g.status === "active" ? "fx-allow" : "fx-deny"}">${esc(g.status)}</td>
        <td>${esc(g.expiresAt.slice(0, 19))}</td>
        <td>${g.status === "active" ? `<button class="btn btn-deny btn-sm" data-grant="${esc(g.id)}">revoke</button>` : ""}</td>
      </tr>`
    )
    .join("");
}

$("grants-table").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-grant]");
  if (!btn) return;
  if (!confirm(`Revoke ${btn.dataset.grant}? Live tokens die on their next call.`)) return;
  await api(`/v1/control/grants/${btn.dataset.grant}/revoke`, {});
  await renderGrants();
});

/* ---------- reports ---------- */

async function renderReports() {
  const r = await api(`/v1/control/reports?tenantId=${tenantId()}`);
  const t = r.totals;
  $("report-tiles").innerHTML = [
    ["calls", t.calls], ["executed", t.executed], ["denied", t.denied],
    ["parked", t.pendingApproval], ["cost units", t.costUnits],
  ]
    .map(([k, v]) => `<div class="tile"><b>${v}</b><span>${k}</span></div>`)
    .join("");
  $("report-table").querySelector("tbody").innerHTML = r.byTool
    .map(
      (x) => `<tr><td>${esc(x.tool)}</td><td>${x.calls}</td><td>${x.executed}</td>
        <td class="${x.denied ? "fx-deny" : ""}">${x.denied}</td><td>${x.costUnits}</td></tr>`
    )
    .join("");
}

/* ---------- channels ---------- */

async function renderChannels() {
  const [channels, bindings] = await Promise.all([
    api(`/v1/control/channels?tenantId=${tenantId()}`),
    api(`/v1/control/slack-bindings?tenantId=${tenantId()}`),
  ]);
  $("channels-table").querySelector("tbody").innerHTML = channels
    .map(
      (c) => `<tr>
        <td>${esc(c.id)}</td><td>${esc(c.config.type)}</td><td>${esc(c.name)}</td>
        <td class="${c.status === "active" ? "fx-allow" : "fx-deny"}">${esc(c.status)}</td>
        <td><button class="btn btn-deny btn-sm" data-channel="${esc(c.id)}">delete</button></td>
      </tr>`
    )
    .join("") || `<tr><td colspan="5" class="empty">no channels — parked approvals only surface here</td></tr>`;
  $("bindings-table").querySelector("tbody").innerHTML = bindings
    .map(
      (b) => `<tr><td>${esc(b.slackUserId)}</td><td>${esc(b.operatorId)}</td><td>${esc(b.createdAt.slice(0, 19))}</td></tr>`
    )
    .join("") || `<tr><td colspan="3" class="empty">no bindings — bind via: toolgate slack bind</td></tr>`;
}

$("chn-add").addEventListener("click", async () => {
  const name = $("chn-name").value.trim();
  const url = $("chn-url").value.trim();
  if (!name || !url) return;
  await api("/v1/control/channels", { tenantId: tenantId(), name, type: "webhook", url });
  $("chn-name").value = ""; $("chn-url").value = "";
  await renderChannels();
});

$("channels-table").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-channel]");
  if (!btn) return;
  if (!confirm(`Delete channel ${btn.dataset.channel}?`)) return;
  await api(`/v1/control/channels/${btn.dataset.channel}`, undefined, "DELETE");
  await renderChannels();
});

/* ---------- oauth connections ---------- */

async function renderConnections() {
  const [apps, connections] = await Promise.all([
    api(`/v1/control/provider-apps?tenantId=${tenantId()}`),
    api(`/v1/control/connections?tenantId=${tenantId()}`),
  ]);
  $("conn-app").innerHTML = apps
    .map((a) => `<option value="${esc(a.id)}">${esc(a.name)} (${esc(a.id)})</option>`)
    .join("") || `<option value="">no provider apps — toolgate oauth add-app</option>`;
  $("connections-table").querySelector("tbody").innerHTML = connections
    .map(
      (c) => `<tr>
        <td>${esc(c.id)}</td><td>${esc(c.userId)}</td><td>${esc(c.providerAppId)}</td>
        <td class="${c.status === "active" ? "fx-allow" : "fx-deny"}">${esc(c.status)}</td>
        <td>${esc(c.expiresAt.slice(0, 19))}</td>
        <td>${c.status === "active" ? `<button class="btn btn-deny btn-sm" data-conn="${esc(c.id)}">revoke</button>` : ""}</td>
      </tr>`
    )
    .join("") || `<tr><td colspan="6" class="empty">no connections yet</td></tr>`;
}

$("conn-start").addEventListener("click", async () => {
  const app = $("conn-app").value;
  const user = $("conn-user").value.trim();
  if (!app || !user) return;
  const out = await api("/v1/control/connections/start", {
    tenantId: tenantId(), userId: user, providerAppId: app,
  });
  const url = $("conn-url");
  url.hidden = false;
  url.innerHTML = `send the user here to authorize: <a href="${esc(out.authorizeUrl)}" target="_blank" rel="noopener">${esc(out.authorizeUrl)}</a>`;
});

$("connections-table").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-conn]");
  if (!btn) return;
  if (!confirm(`Revoke ${btn.dataset.conn}? Sealed tokens are deleted immediately.`)) return;
  await api(`/v1/control/connections/${btn.dataset.conn}/revoke`, {});
  await renderConnections();
});

/* ---------- simulator ---------- */

async function loadPolicies() {
  const policies = await api(`/v1/control/policies?tenantId=${tenantId()}`);
  $("sim-policy").innerHTML = policies
    .map((p) => `<option value="${esc(p.id)}">${esc(p.name)} (${p.rules.length} rules)</option>`)
    .join("");
}

$("sim-run").addEventListener("click", async () => {
  const verdict = $("sim-verdict");
  try {
    const d = await api(`/v1/control/policies/${$("sim-policy").value}/simulate`, {
      upstream: $("sim-upstream").value.trim(),
      tool: $("sim-tool").value.trim(),
      args: JSON.parse($("sim-args").value || "{}"),
      tainted: $("sim-tainted").checked,
    });
    verdict.hidden = false;
    verdict.className = `sim-verdict mono v-${d.effect}`;
    verdict.textContent = `${d.effect} (${d.source}${d.ruleId ? `, rule ${d.ruleId}` : ""}) — ${d.reason}`;
  } catch (err) {
    verdict.hidden = false;
    verdict.className = "sim-verdict mono v-deny";
    verdict.textContent = `${err.code || "error"}: ${err.message}`;
  }
});

/* ---------- boot ---------- */

if (sessionStorage.getItem("tgKey")) {
  connect(sessionStorage.getItem("tgKey")).catch(() => {
    sessionStorage.removeItem("tgKey");
  });
}
