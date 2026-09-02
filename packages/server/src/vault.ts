import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export interface SealedSecret {
  iv: string;
  ct: string;
  tag: string;
}

/**
 * AES-256-GCM secret sealing. The master key never leaves the server process;
 * sealed blobs are what the store persists. KMS envelope encryption is the
 * production upgrade path (issue #8).
 */
export class Vault {
  readonly #key: Buffer;

  constructor(masterKey: string) {
    this.#key = createHash("sha256").update(masterKey).digest();
  }

  seal(plaintext: string): SealedSecret {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.#key, iv);
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return {
      iv: iv.toString("base64"),
      ct: ct.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
    };
  }

  open(sealed: SealedSecret): string {
    const decipher = createDecipheriv("aes-256-gcm", this.#key, Buffer.from(sealed.iv, "base64"));
    decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
    const pt = Buffer.concat([decipher.update(Buffer.from(sealed.ct, "base64")), decipher.final()]);
    return pt.toString("utf8");
  }
}
