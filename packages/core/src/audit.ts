import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import type { JWK } from "jose";
import { canonicalJson } from "./canonical.js";
import type { AuditRecord, AuditRecordInput } from "./types.js";

export const GENESIS_HASH = "0".repeat(64);

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Hash covers seq + prevHash + the whole record body, so order and content are both sealed. */
function computeHash(record: Omit<AuditRecord, "hash" | "sig">): string {
  return sha256Hex(canonicalJson(record));
}

export function appendAuditRecord(
  prev: Pick<AuditRecord, "seq" | "hash"> | null,
  input: AuditRecordInput,
  gatePrivateJwk: JWK,
): AuditRecord {
  const base = {
    ...input,
    seq: prev ? prev.seq + 1 : 1,
    prevHash: prev ? prev.hash : GENESIS_HASH,
  };
  const hash = computeHash(base);
  const sig = signHash(hash, gatePrivateJwk);
  return { ...base, hash, sig };
}

export interface ChainVerification {
  valid: boolean;
  length: number;
  brokenAtSeq?: number;
  reason?: string;
}

export function verifyAuditChain(records: AuditRecord[], gatePublicJwk: JWK): ChainVerification {
  let prevHash = GENESIS_HASH;
  let prevSeq = 0;
  for (const record of records) {
    const { hash, sig, ...body } = record;
    if (record.seq !== prevSeq + 1) {
      return broken(records.length, record.seq, `sequence gap: expected ${prevSeq + 1}`);
    }
    if (record.prevHash !== prevHash) {
      return broken(records.length, record.seq, "prevHash does not match previous record");
    }
    if (computeHash(body) !== hash) {
      return broken(records.length, record.seq, "record content does not match its hash");
    }
    if (!verifyHashSignature(hash, sig, gatePublicJwk)) {
      return broken(records.length, record.seq, "signature invalid");
    }
    prevHash = hash;
    prevSeq = record.seq;
  }
  return { valid: true, length: records.length };
}

function broken(length: number, seq: number, reason: string): ChainVerification {
  return { valid: false, length, brokenAtSeq: seq, reason };
}

function signHash(hashHex: string, privateJwk: JWK): string {
  const key = createPrivateKey({ key: privateJwk as Record<string, unknown>, format: "jwk" });
  return sign(null, Buffer.from(hashHex, "hex"), key).toString("base64url");
}

function verifyHashSignature(hashHex: string, sig: string, publicJwk: JWK): boolean {
  try {
    const key = createPublicKey({ key: publicJwk as Record<string, unknown>, format: "jwk" });
    return verify(null, Buffer.from(hashHex, "hex"), key, Buffer.from(sig, "base64url"));
  } catch {
    return false;
  }
}

/** Hash tool-call args for the audit trail without persisting payload contents. */
export function hashArgs(args: Record<string, unknown>): string {
  return sha256Hex(canonicalJson(args));
}
