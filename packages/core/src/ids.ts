import { randomBytes } from "node:crypto";

/** Crockford-style base32, lowercase, without ambiguous characters (i, l, o, u). */
const ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

export type IdPrefix =
  | "tnt" // tenant
  | "usr" // user (the human principal)
  | "agt" // agent identity
  | "ups" // upstream tool backend
  | "grt" // delegation grant
  | "pol" // policy
  | "apr" // approval request
  | "call" // tool call
  | "evt"; // audit event

/** 20 chars over a 32-symbol alphabet ≈ 100 bits of entropy. */
export function newId(prefix: IdPrefix, size = 20): string {
  const bytes = randomBytes(size);
  let out = "";
  for (const b of bytes) out += ALPHABET[b % 32];
  return `${prefix}_${out}`;
}
