import { serve, type ServerType } from "@hono/node-server";
import { createApp, createAppContext } from "@toolgate/server";
import { ToolgateCallError, ToolgateClient, generateEd25519KeyPair } from "@toolgate/sdk";
import { makeUpstreams } from "./upstream.js";

const GATE_PORT = 8491;
const UPSTREAM_PORT = 8492;
const GATE_URL = `http://localhost:${GATE_PORT}`;
const UPSTREAM_URL = `http://localhost:${UPSTREAM_PORT}`;

const CRM_SECRET = "crm-live-key-7f3a";
const EMAIL_SECRET = "email-live-key-b91c";

const line = (tag: string, msg: string) => console.log(`  [${tag.padEnd(8)}] ${msg}`);
const section = (title: string) => console.log(`\n— ${title} ${"—".repeat(Math.max(1, 72 - title.length))}`);

async function main(): Promise<void> {
  console.log("\nTOOLGATE DEMO — an embedded agent that never holds a credential\n");

  // -- infrastructure ---------------------------------------------------------
  const ctx = await createAppContext({ dbPath: ":memory:", publicUrl: GATE_URL });
  const servers: ServerType[] = [
    serve({ fetch: createApp(ctx).fetch, port: GATE_PORT }),
    serve({ fetch: makeUpstreams({ crm: CRM_SECRET, email: EMAIL_SECRET }).fetch, port: UPSTREAM_PORT }),
  ];
  const admin = { "x-toolgate-admin-key": ctx.config.adminKey, "content-type": "application/json" };
  const adminPost = async (path: string, body: unknown): Promise<Record<string, unknown>> => {
    const res = await fetch(`${GATE_URL}${path}`, {
      method: "POST",
      headers: admin,
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`${path} -> ${res.status}: ${await res.text()}`);
    return (await res.json()) as Record<string, unknown>;
  };

  section("Setup: tenant, human, agent identity, tools, policy, delegation");
  const tenant = await adminPost("/v1/control/tenants", { name: "Acme Corp" });
  const user = await adminPost("/v1/control/users", {
    tenantId: tenant.id,
    displayName: "Sam (account executive)",
    email: "sam@acme.com",
  });
  const agentKeys = await generateEd25519KeyPair();
  const agent = await adminPost("/v1/control/agents", {
    tenantId: tenant.id,
    name: "inbox-assistant",
    publicJwk: agentKeys.publicJwk,
  });
  line("SETUP", `agent '${agent.name}' registered — Toolgate stores only its PUBLIC key`);

  await adminPost("/v1/control/upstreams", {
    tenantId: tenant.id,
    name: "crm",
    baseUrl: `${UPSTREAM_URL}/crm`,
    credential: { mode: "bearer", secret: CRM_SECRET },
    tools: [
      { name: "read_contact", costUnits: 1 },
      { name: "list_contacts", costUnits: 1 },
      { name: "delete_contact", sideEffecting: true, costUnits: 1 },
    ],
  });
  await adminPost("/v1/control/upstreams", {
    tenantId: tenant.id,
    name: "email",
    baseUrl: `${UPSTREAM_URL}/email`,
    credential: { mode: "header", headerName: "X-Api-Key", secret: EMAIL_SECRET },
    tools: [{ name: "send_email", sideEffecting: true, costUnits: 2 }],
  });
  line("SETUP", "upstream credentials sealed into the vault (AES-256-GCM)");

  const policy = await adminPost("/v1/control/policies", {
    tenantId: tenant.id,
    name: "sam-assistant-policy",
    rules: [
      { id: "never-delete", effect: "deny", match: { upstream: "crm", tool: "delete_*" } },
      {
        id: "external-email-needs-human",
        effect: "require_approval",
        match: {
          upstream: "email",
          tool: "send_email",
          where: [{ path: "to", op: "matches", value: "@(?!acme\\.com)" }],
        },
      },
      { id: "internal-email-ok", effect: "allow", match: { upstream: "email", tool: "send_email" } },
      { id: "crm-ok", effect: "allow", match: { upstream: "crm", tool: "*" } },
    ],
  });
  const grant = await adminPost("/v1/control/grants", {
    tenantId: tenant.id,
    userId: user.id,
    agentId: agent.id,
    policyId: policy.id,
    scopes: ["crm", "email"],
    authorization: [
      { upstream: "crm", tools: ["*"] },
      { upstream: "email", tools: ["send_email"] },
    ],
    budgetMaxUnits: 8,
    ttlHours: 8,
  });
  line("SETUP", `Sam delegated bounded authority to the agent (grant ${grant.id}, budget 8 units, 8h)`);

  const client = new ToolgateClient({
    baseUrl: GATE_URL,
    agentId: agent.id as string,
    agentPrivateJwk: agentKeys.privateJwk,
    grantId: grant.id as string,
  });

  // -- scenario -----------------------------------------------------------------
  section("1. Allowed call — credential injected server-side, invisible to the agent");
  const read = await client.call("crm", "read_contact", { contactId: "c-001" });
  if (read.status === "executed") {
    line("OK", `read_contact executed -> ${JSON.stringify(read.result)}`);
    line("NOTE", "the CRM demanded its live API key; the agent never saw it");
  }

  section("2. Policy denial — the agent tries to delete a contact");
  try {
    await client.call("crm", "delete_contact", { contactId: "c-001" });
  } catch (err) {
    if (err instanceof ToolgateCallError) {
      line("DENIED", `${err.code}: ${err.message}`);
    }
  }

  section("3. Human-in-the-loop — external email parks until Sam approves");
  const parked = await client.call("email", "send_email", {
    to: "cfo@globex.com",
    subject: "Renewal proposal",
    body: "Hi — attached the renewal terms we discussed.",
  });
  if (parked.status !== "pending_approval") throw new Error("expected approval parking");
  line("PARKED", `approval ${parked.approvalId} pending — agent is blocked, not trusted`);

  setTimeout(() => {
    void adminPost(`/v1/control/approvals/${parked.approvalId}/decide`, {
      decision: "approve",
      decidedBy: user.id,
    }).then(() => line("HUMAN", "Sam approved the exact parked arguments (args are hash-bound)"));
  }, 1200);

  const sent = await client.waitForApproval(parked.approvalId, { pollMs: 300 });
  line("OK", `send_email executed after approval -> ${JSON.stringify(sent.result)}`);

  section("4. Budget — the delegation runs out of units");
  // Spent so far: 1 (read) + 2 (email) = 3 of 8. Burn past the cap.
  for (let i = 0; i < 6; i++) {
    try {
      await client.call("crm", "list_contacts", { page: i });
      line("OK", `list_contacts page ${i} (1 unit)`);
    } catch (err) {
      if (err instanceof ToolgateCallError && err.code === "TG_BUDGET_EXCEEDED") {
        line("BUDGET", `blocked: ${err.message} — delegation cannot overspend`);
        break;
      }
      throw err;
    }
  }

  section("5. Revocation — Sam pulls the plug while the agent holds a live token");
  await client.token();
  await adminPost(`/v1/control/grants/${grant.id}/revoke`, {});
  try {
    await client.call("crm", "read_contact", { contactId: "c-002" });
  } catch (err) {
    if (err instanceof ToolgateCallError) {
      line("REVOKED", `${err.code}: live token died with the grant, no TTL wait`);
    }
  }

  section("6. Audit — every decision above is in a signed hash chain");
  const auditRes = await fetch(`${GATE_URL}/v1/control/audit/verify`, { headers: admin });
  const verification = (await auditRes.json()) as { valid: boolean; length: number };
  line("AUDIT", `chain of ${verification.length} records — verification: ${verification.valid ? "VALID" : "BROKEN"}`);

  const recordsRes = await fetch(`${GATE_URL}/v1/control/audit?tenantId=${tenant.id}`, { headers: admin });
  const records = (await recordsRes.json()) as {
    action: { tool: string; upstream: string };
    decision: { effect: string; source: string };
    result: { status: string; costUnits?: number };
  }[];
  for (const r of records) {
    line(
      "TRACE",
      `${r.action.upstream}.${r.action.tool.padEnd(14)} ${r.decision.effect.padEnd(16)} (${r.decision.source}) -> ${r.result.status}`,
    );
  }

  console.log(
    "\nSummary: the agent authenticated with its own key, acted under Sam's delegation,",
  );
  console.log(
    "was policy-checked and metered on every call, waited for a human on the risky one,",
  );
  console.log("never touched a real credential, and left a tamper-evident trail.\n");

  for (const s of servers) s.close();
}

main().catch((err) => {
  console.error("demo failed:", err);
  process.exit(1);
});
