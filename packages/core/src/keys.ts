import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from "jose";

export interface KeyPairJwk {
  /** RFC 7638 thumbprint of the public JWK; doubles as `kid` and `cnf.jkt`. */
  kid: string;
  publicJwk: JWK;
  privateJwk: JWK;
}

export async function generateEd25519KeyPair(): Promise<KeyPairJwk> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  publicJwk.kid = kid;
  publicJwk.alg = "EdDSA";
  privateJwk.kid = kid;
  privateJwk.alg = "EdDSA";
  return { kid, publicJwk, privateJwk };
}

export async function jwkThumbprint(publicJwk: JWK): Promise<string> {
  return calculateJwkThumbprint(publicJwk);
}

export async function importSigningKey(privateJwk: JWK) {
  return importJWK(privateJwk, "EdDSA");
}

export async function importVerifyKey(publicJwk: JWK) {
  return importJWK(publicJwk, "EdDSA");
}

export type { JWK };
