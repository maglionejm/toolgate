import { SignJWT, jwtVerify, type JWK } from "jose";
import { randomBytes } from "node:crypto";
import { ErrorCodes, ToolgateError } from "./errors.js";
import { importSigningKey, importVerifyKey } from "./keys.js";
import { CapabilityClaimsSchema, type AuthorizationDetail, type CapabilityClaims } from "./types.js";

export const CAPABILITY_TOKEN_TYP = "tg+jwt";
export const DEFAULT_TOKEN_TTL_SECONDS = 120;

export interface MintCapabilityTokenOptions {
  issuer: string;
  audience: string;
  tenantId: string;
  /** The human principal the work is being done for (token `sub`). */
  userId: string;
  /** The agent doing the work (token `act.sub`). */
  agentId: string;
  grantId: string;
  scopes: string[];
  authorizationDetails: AuthorizationDetail[];
  /** JWK thumbprint of the agent key; the gate demands proofs signed by it. */
  agentJkt: string;
  /** Per-task transaction id; generated when omitted. */
  txn?: string;
  ttlSeconds?: number;
}

/**
 * ±15% jitter on the TTL so a harvested batch of tokens never expires at the
 * same instant and refresh storms don't synchronize.
 */
function jitteredTtlMs(ttlSeconds: number): number {
  const jitter = 1 + (Math.random() * 0.3 - 0.15);
  return Math.max(1000, Math.round(ttlSeconds * 1000 * jitter));
}

export async function mintCapabilityToken(
  controlPlanePrivateJwk: JWK,
  options: MintCapabilityTokenOptions,
): Promise<{ token: string; jti: string; txn: string; expiresAt: Date }> {
  const key = await importSigningKey(controlPlanePrivateJwk);
  const ttl = options.ttlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
  const jti = randomBytes(16).toString("base64url");
  const txn = options.txn ?? `txn_${randomBytes(12).toString("base64url")}`;
  const expiresAt = new Date(Date.now() + (ttl < 0 ? ttl * 1000 : jitteredTtlMs(ttl)));

  const token = await new SignJWT({
    tenant: options.tenantId,
    grant_id: options.grantId,
    act: { sub: options.agentId },
    scope: options.scopes.join(" "),
    authorization_details: options.authorizationDetails,
    cnf: { jkt: options.agentJkt },
    txn,
    tg_ver: 1,
  })
    .setProtectedHeader({
      alg: "EdDSA",
      typ: CAPABILITY_TOKEN_TYP,
      ...(controlPlanePrivateJwk.kid ? { kid: controlPlanePrivateJwk.kid } : {}),
    })
    .setIssuer(options.issuer)
    .setSubject(options.userId)
    .setAudience(options.audience)
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .setJti(jti)
    .sign(key);

  return { token, jti, txn, expiresAt };
}

export interface VerifyCapabilityTokenOptions {
  issuer: string;
  audience: string;
  clockToleranceSeconds?: number;
}

export async function verifyCapabilityToken(
  controlPlanePublicJwk: JWK,
  token: string,
  options: VerifyCapabilityTokenOptions,
): Promise<CapabilityClaims> {
  const key = await importVerifyKey(controlPlanePublicJwk);
  let payload: unknown;
  try {
    const result = await jwtVerify(token, key, {
      issuer: options.issuer,
      audience: options.audience,
      typ: CAPABILITY_TOKEN_TYP,
      clockTolerance: options.clockToleranceSeconds ?? 0,
    });
    payload = result.payload;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('"exp"')) {
      throw new ToolgateError(ErrorCodes.TOKEN_EXPIRED, "capability token expired");
    }
    throw new ToolgateError(ErrorCodes.TOKEN_INVALID, `capability token rejected: ${message}`);
  }

  const parsed = CapabilityClaimsSchema.safeParse(payload);
  if (!parsed.success) {
    throw new ToolgateError(ErrorCodes.TOKEN_INVALID, "capability token claims malformed", {
      issues: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
    });
  }
  return parsed.data;
}
