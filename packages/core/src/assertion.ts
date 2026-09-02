import {
  EmbeddedJWK,
  SignJWT,
  calculateJwkThumbprint,
  decodeProtectedHeader,
  jwtVerify,
  type JWK,
} from "jose";
import { createHash, randomBytes } from "node:crypto";
import { ErrorCodes, ToolgateError } from "./errors.js";
import { importSigningKey, importVerifyKey } from "./keys.js";

export const CLIENT_ASSERTION_TYP = "tg-client+jwt";
export const POP_PROOF_TYP = "tg-pop+jwt";
const PROOF_MAX_AGE_SECONDS = 60;

// ---------------------------------------------------------------------------
// Client assertion (RFC 7523 private_key_jwt style): how an agent
// authenticates to the control plane token endpoint. No shared secrets.
// ---------------------------------------------------------------------------

export async function signClientAssertion(
  agentPrivateJwk: JWK,
  options: { agentId: string; tokenUrl: string; ttlSeconds?: number },
): Promise<string> {
  const key = await importSigningKey(agentPrivateJwk);
  return new SignJWT({})
    .setProtectedHeader({ alg: "EdDSA", typ: CLIENT_ASSERTION_TYP })
    .setIssuer(options.agentId)
    .setSubject(options.agentId)
    .setAudience(options.tokenUrl)
    .setIssuedAt()
    .setExpirationTime(new Date(Date.now() + (options.ttlSeconds ?? 60) * 1000))
    .setJti(randomBytes(12).toString("base64url"))
    .sign(key);
}

export async function verifyClientAssertion(
  agentPublicJwk: JWK,
  assertion: string,
  options: { expectedAudience: string },
): Promise<{ agentId: string; jti: string }> {
  const key = await importVerifyKey(agentPublicJwk);
  try {
    const { payload } = await jwtVerify(assertion, key, {
      audience: options.expectedAudience,
      typ: CLIENT_ASSERTION_TYP,
    });
    if (!payload.iss || payload.iss !== payload.sub || typeof payload.jti !== "string") {
      throw new Error("client assertion must have iss === sub and a jti");
    }
    return { agentId: payload.sub as string, jti: payload.jti };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new ToolgateError(ErrorCodes.TOKEN_INVALID, `client assertion rejected: ${message}`);
  }
}

// ---------------------------------------------------------------------------
// Proof of possession (DPoP-style): every gate call carries a one-time proof
// signed by the agent key named in the capability token's cnf.jkt. A stolen
// token is useless without the key.
// ---------------------------------------------------------------------------

export function accessTokenHash(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

export async function signPopProof(
  agentPrivateJwk: JWK,
  options: { htm: string; htu: string; accessToken: string },
): Promise<string> {
  const key = await importSigningKey(agentPrivateJwk);
  const { kid: _kid, alg: _alg, ...publicJwk } = publicJwkFromPrivate(agentPrivateJwk);
  return new SignJWT({
    htm: options.htm.toUpperCase(),
    htu: options.htu,
    ath: accessTokenHash(options.accessToken),
  })
    .setProtectedHeader({ alg: "EdDSA", typ: POP_PROOF_TYP, jwk: publicJwk })
    .setIssuedAt()
    .setJti(randomBytes(12).toString("base64url"))
    .sign(key);
}

export interface VerifiedPopProof {
  jti: string;
  jkt: string;
}

export async function verifyPopProof(
  proof: string,
  options: { expectedJkt: string; htm: string; htu: string; accessToken: string },
): Promise<VerifiedPopProof> {
  try {
    const header = decodeProtectedHeader(proof);
    if (header.typ !== POP_PROOF_TYP || !header.jwk) {
      throw new Error("missing typ or embedded jwk");
    }
    const jkt = await calculateJwkThumbprint(header.jwk as JWK);
    if (jkt !== options.expectedJkt) {
      throw new Error("proof key does not match token cnf.jkt");
    }
    const { payload } = await jwtVerify(proof, EmbeddedJWK, {
      typ: POP_PROOF_TYP,
      maxTokenAge: PROOF_MAX_AGE_SECONDS,
      clockTolerance: 5,
    });
    if (payload.htm !== options.htm.toUpperCase()) throw new Error("htm mismatch");
    if (payload.htu !== options.htu) throw new Error("htu mismatch");
    if (payload.ath !== accessTokenHash(options.accessToken)) throw new Error("ath mismatch");
    if (typeof payload.jti !== "string") throw new Error("missing jti");
    return { jti: payload.jti, jkt };
  } catch (err) {
    if (err instanceof ToolgateError) throw err;
    const message = err instanceof Error ? err.message : String(err);
    throw new ToolgateError(ErrorCodes.PROOF_INVALID, `proof-of-possession rejected: ${message}`);
  }
}

/** Ed25519 public JWK is the private JWK minus the secret scalar `d`. */
function publicJwkFromPrivate(privateJwk: JWK): JWK {
  const { d: _d, ...rest } = privateJwk;
  return rest;
}
