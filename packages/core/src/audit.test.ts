import { describe, expect, it } from "vitest";
import { appendAuditRecord, hashArgs, verifyAuditChain } from "./audit.js";
import { generateEd25519KeyPair } from "./keys.js";
import type { AuditRecord, AuditRecordInput } from "./types.js";

function makeInput(n: number): AuditRecordInput {
  return {
    id: `evt_${n}`,
    tenantId: "tnt_1",
    ts: new Date(1757000000000 + n * 1000).toISOString(),
    actor: { agentId: "agt_1", userId: "usr_1", grantId: "grt_1", tokenJti: `jti-${n}` },
    action: {
      callId: `call_${n}`,
      upstream: "crm",
      tool: "read_contact",
      argsHash: hashArgs({ contactId: n }),
    },
    decision: { effect: "allow", source: "rule", ruleId: "r1", reason: "allowed" },
    result: { status: "executed", httpStatus: 200, latencyMs: 12, costUnits: 1 },
  };
}

describe("audit chain", () => {
  it("appends and verifies a chain", async () => {
    const gate = await generateEd25519KeyPair();
    const records: AuditRecord[] = [];
    let prev: AuditRecord | null = null;
    for (let n = 1; n <= 5; n++) {
      prev = appendAuditRecord(prev, makeInput(n), gate.privateJwk);
      records.push(prev);
    }
    expect(verifyAuditChain(records, gate.publicJwk)).toMatchObject({ valid: true, length: 5 });
  });

  it("detects content tampering in the middle of the chain", async () => {
    const gate = await generateEd25519KeyPair();
    const records: AuditRecord[] = [];
    let prev: AuditRecord | null = null;
    for (let n = 1; n <= 3; n++) {
      prev = appendAuditRecord(prev, makeInput(n), gate.privateJwk);
      records.push(prev);
    }
    const tampered = structuredClone(records);
    tampered[1]!.decision = { effect: "allow", source: "rule", ruleId: "r1", reason: "cover-up" };
    const result = verifyAuditChain(tampered, gate.publicJwk);
    expect(result.valid).toBe(false);
    expect(result.brokenAtSeq).toBe(2);
  });

  it("detects record removal", async () => {
    const gate = await generateEd25519KeyPair();
    const records: AuditRecord[] = [];
    let prev: AuditRecord | null = null;
    for (let n = 1; n <= 3; n++) {
      prev = appendAuditRecord(prev, makeInput(n), gate.privateJwk);
      records.push(prev);
    }
    const withGap = [records[0]!, records[2]!];
    expect(verifyAuditChain(withGap, gate.publicJwk).valid).toBe(false);
  });

  it("detects re-signing by a different key", async () => {
    const gate = await generateEd25519KeyPair();
    const rogue = await generateEd25519KeyPair();
    const record = appendAuditRecord(null, makeInput(1), rogue.privateJwk);
    expect(verifyAuditChain([record], gate.publicJwk).valid).toBe(false);
  });

  it("accepts an empty chain", async () => {
    const gate = await generateEd25519KeyPair();
    expect(verifyAuditChain([], gate.publicJwk)).toMatchObject({ valid: true, length: 0 });
  });
});
