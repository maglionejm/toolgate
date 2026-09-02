import { describe, expect, it } from "vitest";
import { generateEd25519KeyPair } from "./keys.js";
import { mintCapabilityToken, verifyCapabilityToken } from "./token.js";
import { ToolgateError } from "./errors.js";
import type { AuthorizationDetail } from "./types.js";

const AUTHZ: AuthorizationDetail[] = [
  { type: "toolgate:tool_call", upstream: "crm", tools: ["read_contact", "list_contacts"] },
];

const BASE = {
  issuer: "https://control.toolgate.test",
  audience: "toolgate:gate",
  tenantId: "tnt_1",
  userId: "usr_1",
  agentId: "agt_1",
  grantId: "grt_1",
  scopes: ["crm:read"],
  authorizationDetails: AUTHZ,
  agentJkt: "thumb-1",
};

describe("capability tokens", () => {
  it("mints and verifies with delegation semantics (sub=user, act.sub=agent)", async () => {
    const cp = await generateEd25519KeyPair();
    const { token, jti } = await mintCapabilityToken(cp.privateJwk, BASE);
    const claims = await verifyCapabilityToken(cp.publicJwk, token, {
      issuer: BASE.issuer,
      audience: BASE.audience,
    });
    expect(claims.sub).toBe("usr_1");
    expect(claims.act.sub).toBe("agt_1");
    expect(claims.grant_id).toBe("grt_1");
    expect(claims.tenant).toBe("tnt_1");
    expect(claims.scope).toBe("crm:read");
    expect(claims.cnf.jkt).toBe("thumb-1");
    expect(claims.jti).toBe(jti);
    expect(claims.authorization_details).toEqual(AUTHZ);
  });

  it("rejects expired tokens with TG_TOKEN_EXPIRED", async () => {
    const cp = await generateEd25519KeyPair();
    const { token } = await mintCapabilityToken(cp.privateJwk, { ...BASE, ttlSeconds: -10 });
    await expect(
      verifyCapabilityToken(cp.publicJwk, token, { issuer: BASE.issuer, audience: BASE.audience }),
    ).rejects.toMatchObject({ code: "TG_TOKEN_EXPIRED" });
  });

  it("rejects audience mismatch", async () => {
    const cp = await generateEd25519KeyPair();
    const { token } = await mintCapabilityToken(cp.privateJwk, BASE);
    await expect(
      verifyCapabilityToken(cp.publicJwk, token, { issuer: BASE.issuer, audience: "other" }),
    ).rejects.toBeInstanceOf(ToolgateError);
  });

  it("rejects tokens signed by a different key", async () => {
    const cp = await generateEd25519KeyPair();
    const impostor = await generateEd25519KeyPair();
    const { token } = await mintCapabilityToken(impostor.privateJwk, BASE);
    await expect(
      verifyCapabilityToken(cp.publicJwk, token, { issuer: BASE.issuer, audience: BASE.audience }),
    ).rejects.toMatchObject({ code: "TG_TOKEN_INVALID" });
  });

  it("rejects tampered payloads", async () => {
    const cp = await generateEd25519KeyPair();
    const { token } = await mintCapabilityToken(cp.privateJwk, BASE);
    const [h, p, s] = token.split(".") as [string, string, string];
    const payload = JSON.parse(Buffer.from(p, "base64url").toString());
    payload.scope = "crm:read crm:write email:send";
    const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${s}`;
    await expect(
      verifyCapabilityToken(cp.publicJwk, forged, { issuer: BASE.issuer, audience: BASE.audience }),
    ).rejects.toMatchObject({ code: "TG_TOKEN_INVALID" });
  });
});
