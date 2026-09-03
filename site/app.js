/* Toolgate portal — the simulation is real: the decision logic mirrors the
   gate's policy engine and the audit chain is genuine SHA-256 over canonical
   JSON via Web Crypto, verifiable and tamper-demonstrable in-page. */

"use strict";

/* ---------- utilities ---------- */

function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(
      (k) => JSON.stringify(k) + ":" + canonical(value[k])
    ).join(",") + "}";
  }
  return JSON.stringify(value);
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const short = (h) => h.slice(0, 10) + "…";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const $ = (id) => document.getElementById(id);

/* ---------- hero terminal ---------- */

const TERM_LINES = [
  ["t-dim", "$ uv run toolgate-demo"],
  ["t-hl", ""],
  ["t-hl", "TOOLGATE — an embedded agent that never holds a credential"],
  ["t-dim", ""],
  ["t-ok", "  [OK      ] read_contact executed — credential injected server-side"],
  ["t-deny", "  [DENIED  ] TG_DENIED: matched deny rule never-delete"],
  ["t-park", "  [PARKED  ] approval apr_je44zf pending — agent is blocked, not trusted"],
  ["t-hl", "  [HUMAN   ] Sam approved the exact parked arguments (hash-bound)"],
  ["t-ok", "  [OK      ] send_email executed after approval"],
  ["t-deny", "  [BUDGET  ] blocked: delegation grant budget exhausted"],
  ["t-deny", "  [REVOKED ] live token died with the grant, no TTL wait"],
  ["t-ok", "  [AUDIT   ] chain of 10 records — verification: VALID"],
];

async function playTerminal() {
  const body = $("term-body");
  for (const [cls, text] of TERM_LINES) {
    const line = document.createElement("span");
    line.className = cls;
    body.appendChild(line);
    for (const ch of text) {
      line.textContent += ch;
      if (Math.random() < 0.12) await sleep(1);
    }
    body.appendChild(document.createTextNode("\n"));
    await sleep(text ? 260 : 80);
  }
}

/* ---------- simulation state ---------- */

const SCENARIOS = [
  { id: "read", label: "crm.read_contact", args: { contactId: "c-014" }, upstream: "crm", tool: "read_contact", cost: 1 },
  { id: "delete", label: "crm.delete_contact", args: { contactId: "c-014" }, upstream: "crm", tool: "delete_contact", cost: 1 },
  { id: "ext-mail", label: "email.send_email", args: { to: "cfo@globex.com", subject: "Renewal terms" }, upstream: "email", tool: "send_email", cost: 2 },
  { id: "int-mail", label: "email.send_email", args: { to: "ana@acme.com", subject: "Standup notes" }, upstream: "email", tool: "send_email", cost: 2 },
  { id: "billing", label: "billing.charge_card", args: { amount: 4999 }, upstream: "billing", tool: "charge_card", cost: 1 },
  { id: "replay", label: "crm.read_contact — replayed proof", args: { contactId: "c-014" }, upstream: "crm", tool: "read_contact", cost: 1, replay: true },
];

/* Mirrors the server policy in the panel. */
const AUTHZ = [
  { upstream: "crm", tools: ["*"] },
  { upstream: "email", tools: ["send_email"] },
];

function policyDecide(s) {
  if (s.upstream === "crm" && s.tool.startsWith("delete_")) {
    return { effect: "deny", rule: "never-delete" };
  }
  if (s.upstream === "email" && s.tool === "send_email" && !/@acme\.com$/.test(s.args.to || "")) {
    return { effect: "require_approval", rule: "external-email" };
  }
  if (s.upstream === "email" && s.tool === "send_email") {
    return { effect: "allow", rule: "internal-ok" };
  }
  if (s.upstream === "crm") {
    return { effect: "allow", rule: "crm-ok" };
  }
  return { effect: "deny", rule: "default" };
}

const sim = {
  budget: 8, max: 8, seq: 0, prevHash: "0".repeat(64),
  records: [], busy: false, active: null, tampered: false,
};

/* ---------- simulation UI ---------- */

function renderScenarios() {
  const wrap = $("scenarios");
  for (const s of SCENARIOS) {
    const b = document.createElement("button");
    b.className = "scenario";
    b.innerHTML = `<span>${s.label}${s.replay ? " ↻" : ""}</span>` +
      `<span class="sc-args">${JSON.stringify(s.args)}</span>`;
    b.addEventListener("click", () => runScenario(s, b));
    wrap.appendChild(b);
  }
}

function setStage(name, state, note) {
  const li = document.querySelector(`.stages li[data-stage="${name}"]`);
  li.className = state;
  $("note-" + name).textContent = note || "";
}

function resetStages() {
  for (const li of document.querySelectorAll(".stages li")) { li.className = ""; }
  for (const n of document.querySelectorAll(".stage-note")) n.textContent = "";
  for (const r of document.querySelectorAll(".policy-rules li")) r.classList.remove("hit");
  $("verdict").hidden = true;
  $("approval-box").hidden = true;
}

function showVerdict(kind, text) {
  const v = $("verdict");
  v.hidden = false;
  v.className = "verdict mono v-" + kind;
  v.textContent = text;
}

function updateBudget() {
  $("budget-fill").style.width = (sim.budget / sim.max) * 100 + "%";
  $("budget-num").textContent = `${sim.budget} / ${sim.max} units`;
}

async function appendRecord(s, decision, result) {
  sim.seq += 1;
  const body = {
    seq: sim.seq, tool: `${s.upstream}.${s.tool}`,
    argsHash: (await sha256Hex(canonical(s.args))).slice(0, 16),
    decision, result, prevHash: sim.prevHash,
  };
  const hash = await sha256Hex(canonical(body));
  const rec = { ...body, hash };
  sim.records.push(rec);
  sim.prevHash = hash;
  renderChain();
  $("verify-btn").disabled = false;
  $("tamper-btn").disabled = sim.records.length < 2 || sim.tampered;
}

function renderChain() {
  const wrap = $("chain-body");
  wrap.innerHTML = "";
  for (const r of sim.records) {
    const div = document.createElement("div");
    const cls = r.result === "denied" ? "r-deny" : r.result === "pending_approval" ? "r-park" : "";
    div.className = `chain-rec ${cls}` + (r._tampered ? " tampered" : "");
    div.dataset.prev = short(r.prevHash);
    div.innerHTML =
      `<span class="r-seq">${String(r.seq).padStart(3, "0")}</span>` +
      `<span class="r-what"><b>${r.decision}</b> ${r.tool} → ${r.result}` +
      `${r._tampered ? " <b>[EDITED]</b>" : ""}</span>` +
      `<span class="r-hash">${short(r.hash)}</span>`;
    wrap.appendChild(div);
  }
  $("chain-verdict").textContent = "";
  $("chain-verdict").className = "chain-verdict mono";
}

async function runScenario(s, btn) {
  if (sim.busy) return;
  sim.busy = true;
  document.querySelectorAll(".scenario").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
  resetStages();
  sim.active = s;

  // verify: token + proof
  setStage("verify", "run");
  await sleep(340);
  if (s.replay) {
    setStage("verify", "fail", "proof jti already consumed");
    showVerdict("deny", "401 TG_PROOF_INVALID — one proof, one call. Stolen or replayed proofs are dead on arrival.");
    await appendRecord(s, "proof_replay", "denied");
    sim.busy = false;
    return;
  }
  setStage("verify", "pass", "signature, aud, exp, cnf.jkt proof ok");

  // token bounds
  setStage("bounds", "run");
  await sleep(320);
  const inBounds = AUTHZ.some((d) => d.upstream === s.upstream && (d.tools.includes("*") || d.tools.includes(s.tool)));
  if (!inBounds) {
    setStage("bounds", "fail", "outside authorization_details");
    showVerdict("deny", "403 TG_DENIED (token_bounds) — the grant never delegated this upstream. Policy never even ran.");
    await appendRecord(s, "token_bounds", "denied");
    sim.busy = false;
    return;
  }
  setStage("bounds", "pass", "within authorization_details");

  // policy
  setStage("policy", "run");
  await sleep(340);
  const d = policyDecide(s);
  document.querySelector(`.policy-rules li[data-rule="${d.rule}"]`)?.classList.add("hit");
  if (d.effect === "deny") {
    setStage("policy", "fail", `matched deny rule ${d.rule}`);
    showVerdict("deny", `403 TG_DENIED — rule "${d.rule}". Denials are audited too.`);
    await appendRecord(s, `deny:${d.rule}`, "denied");
    sim.busy = false;
    return;
  }
  if (d.effect === "require_approval") {
    setStage("policy", "park", `rule ${d.rule}: human required`);
    showVerdict("park", "202 pending_approval — call parked, arguments frozen.");
    await appendRecord(s, `approval:${d.rule}`, "pending_approval");
    $("approval-box").hidden = false;
    sim.busy = false;
    return;
  }
  setStage("policy", "pass", `matched allow rule ${d.rule}`);

  await finishExecution(s, `allow:${d.rule}`);
  sim.busy = false;
}

async function finishExecution(s, decision) {
  setStage("budget", "run");
  await sleep(300);
  if (sim.budget < s.cost) {
    setStage("budget", "fail", `needs ${s.cost}, ${sim.budget} left`);
    showVerdict("deny", "403 TG_BUDGET_EXCEEDED — the delegation cannot overspend, ever.");
    await appendRecord(s, "budget", "denied");
    return;
  }
  sim.budget -= s.cost;
  updateBudget();
  setStage("budget", "pass", `charged ${s.cost}, ${sim.budget} remaining`);

  setStage("execute", "run", "sealing credential into request…");
  await sleep(420);
  setStage("execute", "pass", "upstream 200 — agent never saw the key");
  showVerdict("allow", "200 executed — result relayed to the agent; credential stayed in the vault.");
  await appendRecord(s, decision, "executed");
}

/* approval flow */
$("approve-btn").addEventListener("click", async () => {
  if (sim.busy || !sim.active) return;
  sim.busy = true;
  $("approval-box").hidden = true;
  await finishExecution(sim.active, "approval:sam");
  sim.busy = false;
});
$("deny-btn").addEventListener("click", async () => {
  if (sim.busy || !sim.active) return;
  $("approval-box").hidden = true;
  showVerdict("deny", "403 TG_APPROVAL_DENIED — Sam said no. The stored arguments can never run.");
  await appendRecord(sim.active, "approval_denied", "denied");
});

/* chain verify + tamper */
$("verify-btn").addEventListener("click", async () => {
  let prev = "0".repeat(64);
  for (const r of sim.records) {
    const { hash, _tampered, ...body } = r;
    const recomputed = await sha256Hex(canonical(body));
    const row = document.querySelectorAll(".chain-rec")[r.seq - 1];
    if (r.prevHash !== prev || recomputed !== hash) {
      const cv = $("chain-verdict");
      cv.textContent = `valid: false · broken_at_seq: ${r.seq} — record content does not match its hash`;
      cv.className = "chain-verdict mono bad";
      document.querySelectorAll(".chain-rec").forEach((el, i) => {
        if (i >= r.seq - 1) el.classList.add("broken");
      });
      row?.classList.add("tampered");
      return;
    }
    prev = hash;
  }
  const cv = $("chain-verdict");
  cv.textContent = `valid: true · length: ${sim.records.length} — every record sealed, in order, untouched`;
  cv.className = "chain-verdict mono ok";
});

$("tamper-btn").addEventListener("click", () => {
  const target = sim.records[1];
  if (!target) return;
  target.decision = "allow:cover-up";
  target.result = "executed";
  target._tampered = true;
  sim.tampered = true;
  $("tamper-btn").disabled = true;
  renderChain();
  document.querySelectorAll(".chain-rec")[1]?.classList.add("tampered");
  const cv = $("chain-verdict");
  cv.textContent = "record 002 edited in storage — now press verify chain";
  cv.className = "chain-verdict mono bad";
});

$("reset-sim").addEventListener("click", () => {
  Object.assign(sim, { budget: 8, seq: 0, prevHash: "0".repeat(64), records: [], active: null, tampered: false, busy: false });
  updateBudget();
  resetStages();
  renderChain();
  $("chain-body").innerHTML = '<p class="chain-empty mono">— no records yet. send a call through the gate. —</p>';
  $("verify-btn").disabled = true;
  $("tamper-btn").disabled = true;
  document.querySelectorAll(".scenario").forEach((b) => b.classList.remove("active"));
});

/* ---------- token anatomy hover ---------- */

for (const span of document.querySelectorAll(".token-json [data-claim]")) {
  span.addEventListener("mouseenter", () => {
    const c = span.dataset.claim;
    document.querySelectorAll("[data-claim]").forEach((el) =>
      el.classList.toggle("lit", el.dataset.claim === c));
  });
  span.addEventListener("mouseleave", () => {
    document.querySelectorAll("[data-claim]").forEach((el) => el.classList.remove("lit"));
  });
}

/* ---------- reveal on scroll ---------- */

const io = new IntersectionObserver((entries) => {
  for (const e of entries) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
}, { threshold: 0.12 });
document.querySelectorAll(".reveal").forEach((el) => io.observe(el));

/* ---------- boot ---------- */

renderScenarios();
updateBudget();
playTerminal();
