import { beforeAll, describe, expect, it } from "vitest";
import type { Hono } from "hono";
import {
  generateEd25519KeyPair,
  signClientAssertion,
  signPopProof,
  type KeyPairJwk,
} from "@toolgate/core";
import { createApp } from "./app.js";
import { createAppContext, type AppContext } from "./context.js";

const PUBLIC_URL = "http://localhost";

/** Records upstream calls so tests can assert on credential injection. */
function makeUpstreamStub() {
  const calls: { url: string; headers: Record<string, string>; body: unknown }[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const headers = Object.fromEntries(
      Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [
        k.toLowerCase(),
        v,
      ]),
    );
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url: input.toString(), headers, body });
    return Response.json({ ok: true, echo: body });
  }) as typeof fetch;
  return { calls, fetchImpl };
}

describe("toolgate server end-to-end", () => {
  let ctx: AppContext;
  let app: Hono;
  let agentKeys: KeyPairJwk;
  let upstreamCalls: ReturnType<typeof makeUpstreamStub>["calls"];
  let admin: Record<string, string>;
  let tenantId: string;
  let userId: string;
  let agentId: string;
  let policyId: string;
  let grantId: string;

  async function adminPost(path: string, body: unknown): Promise<Record<string, unknown>> {
    const res = await app.request(path, {
      method: "POST",
      headers: { ...admin, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(res.status, `POST ${path} -> ${res.status}`).toBeLessThan(300);
    return (await res.json()) as Record<string, unknown>;
  }

  async function getToken(): Promise<string> {
    const assertion = await signClientAssertion(agentKeys.privateJwk, {
      agentId,
      tokenUrl: `${PUBLIC_URL}/v1/token`,
    });
    const res = await app.request("/v1/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        client_assertion: assertion,
        grant_id: grantId,
      }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { access_token: string };
    return json.access_token;
  }

  async function gateCall(
    token: string,
    upstream: string,
    tool: string,
    args: Record<string, unknown>,
  ): Promise<Response> {
    const path = `/v1/gate/call/${upstream}`;
    const proof = await signPopProof(agentKeys.privateJwk, {
      htm: "POST",
      htu: `${PUBLIC_URL}${path}`,
      accessToken: token,
    });
    return app.request(path, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "x-toolgate-proof": proof,
        "content-type": "application/json",
      },
      body: JSON.stringify({ tool, args }),
    });
  }

  beforeAll(async () => {
    const stub = makeUpstreamStub();
    upstreamCalls = stub.calls;
    ctx = await createAppContext({
      dbPath: ":memory:",
      publicUrl: PUBLIC_URL,
      fetchImpl: stub.fetchImpl,
    });
    app = createApp(ctx);
    admin = { "x-toolgate-admin-key": ctx.config.adminKey };
    agentKeys = await generateEd25519KeyPair();

    tenantId = (await adminPost("/v1/control/tenants", { name: "Acme" })).id as string;
    userId = (
      await adminPost("/v1/control/users", { tenantId, displayName: "Sam", email: "sam@acme.com" })
    ).id as string;
    agentId = (
      await adminPost("/v1/control/agents", {
        tenantId,
        name: "assistant",
        publicJwk: agentKeys.publicJwk,
      })
    ).id as string;

    await adminPost("/v1/control/upstreams", {
      tenantId,
      name: "crm",
      baseUrl: "https://crm.internal",
      credential: { mode: "bearer", secret: "crm-secret-123" },
      tools: [
        { name: "read_contact", costUnits: 1 },
        { name: "delete_contact", sideEffecting: true, costUnits: 1 },
      ],
    });
    await adminPost("/v1/control/upstreams", {
      tenantId,
      name: "email",
      baseUrl: "https://mail.internal",
      credential: { mode: "header", headerName: "X-Api-Key", secret: "mail-secret-456" },
      tools: [{ name: "send_email", sideEffecting: true, costUnits: 2 }],
    });

    policyId = (
      await adminPost("/v1/control/policies", {
        tenantId,
        name: "default",
        rules: [
          { id: "no-deletes", effect: "deny", match: { upstream: "crm", tool: "delete_*" } },
          {
            id: "approve-external-email",
            effect: "require_approval",
            match: {
              upstream: "email",
              tool: "send_email",
              where: [{ path: "to", op: "matches", value: "@(?!acme\\.com)" }],
            },
          },
          { id: "allow-email", effect: "allow", match: { upstream: "email", tool: "send_email" } },
          { id: "allow-crm", effect: "allow", match: { upstream: "crm", tool: "*" } },
        ],
      })
    ).id as string;

    grantId = (
      await adminPost("/v1/control/grants", {
        tenantId,
        userId,
        agentId,
        policyId,
        scopes: ["crm:read", "email:send"],
        authorization: [
          { upstream: "crm", tools: ["*"] },
          { upstream: "email", tools: ["send_email"] },
        ],
        budgetMaxUnits: 7,
      })
    ).id as string;
  });

  it("executes an allowed call and injects the real credential upstream", async () => {
    const token = await getToken();
    const res = await gateCall(token, "crm", "read_contact", { contactId: "c1" });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { status: string; result: { ok: boolean } };
    expect(json.status).toBe("executed");
    expect(json.result.ok).toBe(true);

    const upstream = upstreamCalls.at(-1)!;
    expect(upstream.url).toBe("https://crm.internal/tools/read_contact");
    expect(upstream.headers.authorization).toBe("Bearer crm-secret-123");
    expect(upstream.body).toEqual({ contactId: "c1" });
  });

  it("never leaks the credential to the agent-facing response", async () => {
    const token = await getToken();
    const res = await gateCall(token, "crm", "read_contact", { contactId: "c2" });
    expect(JSON.stringify(await res.json())).not.toContain("crm-secret-123");
  });

  it("denies policy-blocked tools and audits the denial", async () => {
    const token = await getToken();
    const res = await gateCall(token, "crm", "delete_contact", { contactId: "c1" });
    expect(res.status).toBe(403);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe("TG_DENIED");

    const audit = ctx.store.listAudit(tenantId);
    const denial = audit.at(-1)!;
    expect(denial.decision.effect).toBe("deny");
    expect(denial.result.status).toBe("denied");
    expect(denial.action.tool).toBe("delete_contact");
  });

  it("rejects replayed proofs", async () => {
    const token = await getToken();
    const path = "/v1/gate/call/crm";
    const proof = await signPopProof(agentKeys.privateJwk, {
      htm: "POST",
      htu: `${PUBLIC_URL}${path}`,
      accessToken: token,
    });
    const make = () =>
      app.request(path, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "x-toolgate-proof": proof,
          "content-type": "application/json",
        },
        body: JSON.stringify({ tool: "read_contact", args: {} }),
      });
    expect((await make()).status).toBe(200);
    const replay = await make();
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as { error: { code: string } }).error.code).toBe(
      "TG_PROOF_INVALID",
    );
  });

  it("rejects replayed client assertions at the token endpoint", async () => {
    const assertion = await signClientAssertion(agentKeys.privateJwk, {
      agentId,
      tokenUrl: `${PUBLIC_URL}/v1/token`,
    });
    const body = JSON.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      client_assertion: assertion,
      grant_id: grantId,
    });
    const first = await app.request("/v1/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(first.status).toBe(200);
    const second = await app.request("/v1/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(second.status).toBe(401);
  });

  it("parks external email behind approval, executes only the approved args", async () => {
    const token = await getToken();
    const res = await gateCall(token, "email", "send_email", {
      to: "ceo@bigcorp.com",
      subject: "Q3 numbers",
    });
    expect(res.status).toBe(202);
    const parked = (await res.json()) as { status: string; approval_id: string };
    expect(parked.status).toBe("pending_approval");

    // Status poll (token-only endpoint).
    const poll = await app.request(`/v1/gate/approvals/${parked.approval_id}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(((await poll.json()) as { status: string }).status).toBe("pending");

    // Executing before decision is rejected as pending.
    const early = await executeApproval(token, parked.approval_id);
    expect(early.status).toBe(409);

    // Human approves via control plane.
    const decided = await adminPost(`/v1/control/approvals/${parked.approval_id}/decide`, {
      decision: "approve",
      decidedBy: userId,
    });
    expect(decided.status).toBe("approved");

    // Agent executes the parked call — stored args, credential injected.
    const exec = await executeApproval(token, parked.approval_id);
    expect(exec.status).toBe(200);
    const upstream = upstreamCalls.at(-1)!;
    expect(upstream.url).toBe("https://mail.internal/tools/send_email");
    expect(upstream.headers["x-api-key"]).toBe("mail-secret-456");
    expect(upstream.body).toEqual({ to: "ceo@bigcorp.com", subject: "Q3 numbers" });

    // Double execution is blocked.
    const again = await executeApproval(token, parked.approval_id);
    expect(again.status).toBe(403);
  });

  async function executeApproval(token: string, approvalId: string): Promise<Response> {
    const path = `/v1/gate/approvals/${approvalId}/execute`;
    const proof = await signPopProof(agentKeys.privateJwk, {
      htm: "POST",
      htu: `${PUBLIC_URL}${path}`,
      accessToken: token,
    });
    return app.request(path, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "x-toolgate-proof": proof },
    });
  }

  it("exhausts the budget and blocks further calls", async () => {
    // Budget 7: spent so far read(1)+read(1)+read(1)+email(2) = 5. Two more units left.
    const token = await getToken();
    expect((await gateCall(token, "crm", "read_contact", { n: 1 })).status).toBe(200);
    expect((await gateCall(token, "crm", "read_contact", { n: 2 })).status).toBe(200);
    const broke = await gateCall(token, "crm", "read_contact", { n: 3 });
    expect(broke.status).toBe(403);
    expect(((await broke.json()) as { error: { code: string } }).error.code).toBe(
      "TG_BUDGET_EXCEEDED",
    );
  });

  it("revocation kills live tokens immediately", async () => {
    const token = await getToken();
    await adminPost(`/v1/control/grants/${grantId}/revoke`, {});
    const res = await gateCall(token, "crm", "read_contact", { n: 9 });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("TG_REVOKED");
  });

  it("audit chain stays verifiable end-to-end", async () => {
    const res = await app.request("/v1/control/audit/verify", { headers: admin });
    const verification = (await res.json()) as { valid: boolean; length: number };
    expect(verification.valid).toBe(true);
    expect(verification.length).toBeGreaterThanOrEqual(8);
  });

  it("control plane requires the admin key", async () => {
    const res = await app.request("/v1/control/audit", {});
    expect(res.status).toBe(401);
  });
});
