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

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
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

let view = "approvals";
let pollTimer = null;

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
  if (view === "approvals") {
    await renderApprovals();
    pollTimer = setInterval(renderApprovals, 4000);
  } else if (view === "audit") await renderAudit();
  else if (view === "grants") await renderGrants();
  else if (view === "simulator") await loadPolicies();
  else if (view === "reports") await renderReports();
}

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
        <button class="btn btn-primary btn-sm" data-act="approve">Approve exactly this</button>
        <button class="btn btn-deny btn-sm" data-act="deny">Deny</button>
      </div>`
    )
    .join("");
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
