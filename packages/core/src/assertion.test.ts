import { describe, expect, it } from "vitest";
import {
  signClientAssertion,
  signPopProof,
  verifyClientAssertion,
  verifyPopProof,
} from "./assertion.js";
import { generateEd25519KeyPair } from "./keys.js";

describe("client assertions", () => {
  it("verifies a valid assertion", async () => {
    const agent = await generateEd25519KeyPair();
    const assertion = await signClientAssertion(agent.privateJwk, {
      agentId: "agt_1",
      tokenUrl: "https://control.toolgate.test/v1/token",
    });
    const result = await verifyClientAssertion(agent.publicJwk, assertion, {
      expectedAudience: "https://control.toolgate.test/v1/token",
    });
    expect(result.agentId).toBe("agt_1");
    expect(result.jti.length).toBeGreaterThan(8);
  });

  it("rejects an assertion for a different audience", async () => {
    const agent = await generateEd25519KeyPair();
    const assertion = await signClientAssertion(agent.privateJwk, {
      agentId: "agt_1",
      tokenUrl: "https://evil.example/token",
    });
    await expect(
      verifyClientAssertion(agent.publicJwk, assertion, {
        expectedAudience: "https://control.toolgate.test/v1/token",
      }),
    ).rejects.toMatchObject({ code: "TG_TOKEN_INVALID" });
  });
});

describe("proof of possession", () => {
  const call = {
    htm: "POST",
    htu: "https://gate.toolgate.test/v1/call/crm",
    accessToken: "token-abc",
  };

  it("verifies a proof signed by the bound key", async () => {
    const agent = await generateEd25519KeyPair();
    const proof = await signPopProof(agent.privateJwk, call);
    const verified = await verifyPopProof(proof, { ...call, expectedJkt: agent.kid });
    expect(verified.jkt).toBe(agent.kid);
  });

  it("rejects a proof from a different key (stolen token scenario)", async () => {
    const agent = await generateEd25519KeyPair();
    const thief = await generateEd25519KeyPair();
    const proof = await signPopProof(thief.privateJwk, call);
    await expect(verifyPopProof(proof, { ...call, expectedJkt: agent.kid })).rejects.toMatchObject({
      code: "TG_PROOF_INVALID",
    });
  });

  it("rejects a proof bound to a different token", async () => {
    const agent = await generateEd25519KeyPair();
    const proof = await signPopProof(agent.privateJwk, { ...call, accessToken: "other-token" });
    await expect(verifyPopProof(proof, { ...call, expectedJkt: agent.kid })).rejects.toMatchObject({
      code: "TG_PROOF_INVALID",
    });
  });

  it("rejects a proof replayed against a different URL", async () => {
    const agent = await generateEd25519KeyPair();
    const proof = await signPopProof(agent.privateJwk, call);
    await expect(
      verifyPopProof(proof, {
        ...call,
        htu: "https://gate.toolgate.test/v1/call/email",
        expectedJkt: agent.kid,
      }),
    ).rejects.toMatchObject({ code: "TG_PROOF_INVALID" });
  });
});
