import { randomBytes } from "node:crypto";
import {
  appendAuditRecord,
  generateEd25519KeyPair,
  verifyAuditChain,
  type AuditRecord,
  type AuditRecordInput,
  type ChainVerification,
  type KeyPairJwk,
} from "@toolgate/core";
import { Store } from "./store.js";
import { Vault } from "./vault.js";

export interface ServerConfig {
  issuer: string;
  gateAudience: string;
  /** External base URL used as the htu binding for PoP proofs. */
  publicUrl: string;
  adminKey: string;
  tokenTtlSeconds: number;
  maxTokenTtlSeconds: number;
  approvalTtlSeconds: number;
}

export interface AppContext {
  store: Store;
  vault: Vault;
  audit: AuditLog;
  config: ServerConfig;
  keys: { control: KeyPairJwk; gate: KeyPairJwk };
  fetchImpl: typeof fetch;
}

export class AuditLog {
  #store: Store;
  #keys: KeyPairJwk;
  #last: AuditRecord | null = null;

  constructor(store: Store, gateKeys: KeyPairJwk) {
    this.#store = store;
    this.#keys = gateKeys;
    this.#last = store.lastAudit() ?? null;
  }

  record(input: AuditRecordInput): AuditRecord {
    const record = appendAuditRecord(this.#last, input, this.#keys.privateJwk);
    this.#store.appendAudit(record);
    this.#last = record;
    return record;
  }

  verify(): ChainVerification {
    return verifyAuditChain(this.#store.listAudit(), this.#keys.publicJwk);
  }
}

export interface CreateContextOptions {
  dbPath?: string;
  publicUrl?: string;
  issuer?: string;
  adminKey?: string;
  masterKey?: string;
  fetchImpl?: typeof fetch;
}

async function loadOrCreateKeys(store: Store, name: string): Promise<KeyPairJwk> {
  const existing = store.getSetting(`keys:${name}`);
  if (existing) return JSON.parse(existing) as KeyPairJwk;
  const keys = await generateEd25519KeyPair();
  store.setSetting(`keys:${name}`, JSON.stringify(keys));
  return keys;
}

export async function createAppContext(options: CreateContextOptions = {}): Promise<AppContext> {
  const store = new Store(options.dbPath ?? process.env.TOOLGATE_DB ?? "toolgate.db");

  let masterKey = options.masterKey ?? process.env.TOOLGATE_MASTER_KEY;
  if (!masterKey) {
    masterKey = store.getSetting("dev_master_key") ?? randomBytes(32).toString("base64url");
    store.setSetting("dev_master_key", masterKey);
    console.warn(
      "[toolgate] DEV MODE: vault master key stored alongside data. Set TOOLGATE_MASTER_KEY in production.",
    );
  }

  let adminKey = options.adminKey ?? process.env.TOOLGATE_ADMIN_KEY;
  if (!adminKey) {
    adminKey = store.getSetting("admin_key") ?? `tgk_${randomBytes(24).toString("base64url")}`;
    store.setSetting("admin_key", adminKey);
  }

  const publicUrl = options.publicUrl ?? process.env.TOOLGATE_PUBLIC_URL ?? "http://localhost:8484";
  const config: ServerConfig = {
    issuer: options.issuer ?? process.env.TOOLGATE_ISSUER ?? publicUrl,
    gateAudience: "toolgate:gate",
    publicUrl,
    adminKey,
    tokenTtlSeconds: 120,
    maxTokenTtlSeconds: 300,
    approvalTtlSeconds: 600,
  };

  const control = await loadOrCreateKeys(store, "control");
  const gate = await loadOrCreateKeys(store, "gate");

  return {
    store,
    vault: new Vault(masterKey),
    audit: new AuditLog(store, gate),
    config,
    keys: { control, gate },
    fetchImpl: options.fetchImpl ?? fetch,
  };
}
