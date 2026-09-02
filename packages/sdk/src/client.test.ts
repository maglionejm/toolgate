import { beforeAll, describe, expect, it } from "vitest";
import { generateEd25519KeyPair, type KeyPairJwk } from "@toolgate/core";
import { createApp, createAppContext, type AppContext } from "@toolgate/server";
import type { Hono } from "hono";
import { ToolgateCallError, ToolgateClient } from "./client.js";

const BASE = "http://localhost";

describe("ToolgateClient against a live in-process server", () => {
  let ctx: AppContext;
  let app: Hono;
  let client: ToolgateClient;
  let agentKeys: KeyPairJwk;
  let tokenExchanges = 0;
  let admin: Record<string, string>;
  let tenantId: string;
  let userId: string;

  async function adminPost(path: string, body: unknown): Promise<Record<string, unknown>> {
    const res = await app.request(path, {
      method: "POST",
      headers: { ...admin, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(res.status).toBeLessThan(300);
    return (await res.json()) as Record<string, unknown>;
  }

  beforeAll(async () => {
    ctx = await createAppContext({
      dbPath: ":memory:",
      publicUrl: BASE,
      fetchImpl: (async () => Response.json({ ok: true })) as typeof fetch,
    });
    app = createApp(ctx);
    admin = { "x-toolgate-admin-key": ctx.config.adminKey };
    agentKeys = await generateEd25519KeyPair();

    tenantId = (await adminPost("/v1/control/tenants", { name: "Acme" })).id as string;
    userId = (await adminPost("/v1/control/users", { tenantId, displayName: "Sam" })).id as string;
    const agentId = (
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
      credential: { mode: "bearer", secret: "s3cret" },
      tools: [
        { name: "read_contact", costUnits: 1 },
        { name: "wire_money", sideEffecting: true, costUnits: 1 },
        { name: "drop_database", sideEffecting: true, costUnits: 1 },
      ],
    });
    const policyId = (
      await adminPost("/v1/control/policies", {
        tenantId,
        name: "default",
        rules: [
          { effect: "deny", match: { tool: "drop_*" } },
          { effect: "require_approval", match: { tool: "wire_money" } },
          { effect: "allow", match: { upstream: "crm" } },
        ],
      })
    ).id as string;
    const grantId = (
      await adminPost("/v1/control/grants", {
        tenantId,
        userId,
        agentId,
        policyId,
        authorization: [{ upstream: "crm", tools: ["*"] }],
        budgetMaxUnits: 100,
      })
    ).id as string;

    // Bridge SDK fetch into the in-process Hono app, counting token exchanges.
    const bridged = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith("/v1/token")) tokenExchanges++;
      return app.request(url, init);
    }) as typeof fetch;

    client = new ToolgateClient({
      baseUrl: BASE,
      agentId,
      agentPrivateJwk: agentKeys.privateJwk,
      grantId,
      fetchImpl: bridged,
    });
  });

  it("executes allowed calls and reuses the cached token", async () => {
    const first = await client.call("crm", "read_contact", { id: "c1" });
    const second = await client.call("crm", "read_contact", { id: "c2" });
    expect(first.status).toBe("executed");
    expect(second.status).toBe("executed");
    expect(tokenExchanges).toBe(1);
  });

  it("throws typed errors on denial", async () => {
    await expect(client.call("crm", "drop_database")).rejects.toMatchObject({
      code: "TG_DENIED",
      httpStatus: 403,
    });
    await expect(client.call("crm", "drop_database")).rejects.toBeInstanceOf(ToolgateCallError);
  });

  it("runs the full approval flow: park, human approves, execute", async () => {
    const parked = await client.call("crm", "wire_money", { amount: 100, to: "ACME-42" });
    expect(parked.status).toBe("pending_approval");
    if (parked.status !== "pending_approval") return;

    // Human approval arrives while the agent is polling.
    const approve = setTimeout(() => {
      void adminPost(`/v1/control/approvals/${parked.approvalId}/decide`, {
        decision: "approve",
        decidedBy: userId,
      });
    }, 300);

    const executed = await client.waitForApproval(parked.approvalId, { pollMs: 100 });
    clearTimeout(approve);
    expect(executed.status).toBe("executed");
    expect((executed.result as { ok: boolean }).ok).toBe(true);
  });

  it("surfaces denial while waiting for approval", async () => {
    const parked = await client.call("crm", "wire_money", { amount: 999999, to: "SHELL-CO" });
    if (parked.status !== "pending_approval") throw new Error("expected approval");

    setTimeout(() => {
      void adminPost(`/v1/control/approvals/${parked.approvalId}/decide`, {
        decision: "deny",
        decidedBy: userId,
      });
    }, 200);

    await expect(
      client.waitForApproval(parked.approvalId, { pollMs: 100 }),
    ).rejects.toMatchObject({ code: "TG_APPROVAL_DENIED" });
  });
});
