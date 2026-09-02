import { DatabaseSync } from "node:sqlite";
import type {
  AgentIdentity,
  ApprovalRequest,
  AuditRecord,
  DelegationGrant,
  Policy,
  Tenant,
  Upstream,
  User,
} from "@toolgate/core";
import type { SealedSecret } from "./vault.js";

/**
 * Single-file SQLite persistence. Entities are stored as JSON documents with
 * the columns needed for lookups; swapping this class for Postgres is the
 * designated scale path (issue #16).
 */
export class Store {
  readonly db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS entities (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        tenant_id TEXT,
        json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_entities_kind_tenant ON entities(kind, tenant_id);
      CREATE TABLE IF NOT EXISTS grant_budgets (
        grant_id TEXT PRIMARY KEY,
        max_units INTEGER NOT NULL,
        spent_units INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS used_jtis (
        jti TEXT NOT NULL,
        kind TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (jti, kind)
      );
      CREATE TABLE IF NOT EXISTS secrets (
        ref TEXT PRIMARY KEY,
        iv TEXT NOT NULL,
        ct TEXT NOT NULL,
        tag TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit (
        seq INTEGER PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        json TEXT NOT NULL
      );
    `);
  }

  // -- settings -------------------------------------------------------------

  getSetting(key: string): string | undefined {
    const row = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as
      | { value: string }
      | undefined;
    return row?.value;
  }

  setSetting(key: string, value: string): void {
    this.db
      .prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(key, value);
  }

  // -- generic entities -----------------------------------------------------

  private put(kind: string, id: string, tenantId: string | null, doc: unknown): void {
    this.db
      .prepare(
        "INSERT INTO entities (id, kind, tenant_id, json) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET json = excluded.json",
      )
      .run(id, kind, tenantId, JSON.stringify(doc));
  }

  private getById<T>(kind: string, id: string): T | undefined {
    const row = this.db
      .prepare("SELECT json FROM entities WHERE id = ? AND kind = ?")
      .get(id, kind) as { json: string } | undefined;
    return row ? (JSON.parse(row.json) as T) : undefined;
  }

  private listByTenant<T>(kind: string, tenantId: string): T[] {
    const rows = this.db
      .prepare("SELECT json FROM entities WHERE kind = ? AND tenant_id = ? ORDER BY id")
      .all(kind, tenantId) as { json: string }[];
    return rows.map((r) => JSON.parse(r.json) as T);
  }

  // -- typed accessors --------------------------------------------------------

  putTenant(t: Tenant): void {
    this.put("tenant", t.id, t.id, t);
  }
  getTenant(id: string): Tenant | undefined {
    return this.getById("tenant", id);
  }

  putUser(u: User): void {
    this.put("user", u.id, u.tenantId, u);
  }
  getUser(id: string): User | undefined {
    return this.getById("user", id);
  }

  putAgent(a: AgentIdentity): void {
    this.put("agent", a.id, a.tenantId, a);
  }
  getAgent(id: string): AgentIdentity | undefined {
    return this.getById("agent", id);
  }

  putUpstream(u: Upstream): void {
    this.put("upstream", u.id, u.tenantId, u);
  }
  getUpstream(id: string): Upstream | undefined {
    return this.getById("upstream", id);
  }
  findUpstreamByName(tenantId: string, name: string): Upstream | undefined {
    return this.listByTenant<Upstream>("upstream", tenantId).find((u) => u.name === name);
  }

  putPolicy(p: Policy): void {
    this.put("policy", p.id, p.tenantId, p);
  }
  getPolicy(id: string): Policy | undefined {
    return this.getById("policy", id);
  }

  putGrant(g: DelegationGrant): void {
    this.put("grant", g.id, g.tenantId, g);
    this.db
      .prepare(
        "INSERT INTO grant_budgets (grant_id, max_units, spent_units) VALUES (?, ?, ?) ON CONFLICT(grant_id) DO UPDATE SET max_units = excluded.max_units",
      )
      .run(g.id, g.budget.maxUnits, g.budget.spentUnits);
  }
  getGrant(id: string): DelegationGrant | undefined {
    const grant = this.getById<DelegationGrant>("grant", id);
    if (!grant) return undefined;
    const budget = this.db
      .prepare("SELECT max_units, spent_units FROM grant_budgets WHERE grant_id = ?")
      .get(id) as { max_units: number; spent_units: number } | undefined;
    if (budget) {
      grant.budget = { maxUnits: budget.max_units, spentUnits: budget.spent_units };
    }
    return grant;
  }

  /** Atomic conditional charge; returns false when the budget cannot cover the cost. */
  chargeBudget(grantId: string, costUnits: number): boolean {
    const result = this.db
      .prepare(
        "UPDATE grant_budgets SET spent_units = spent_units + ? WHERE grant_id = ? AND spent_units + ? <= max_units",
      )
      .run(costUnits, grantId, costUnits);
    return result.changes === 1;
  }

  putApproval(a: ApprovalRequest): void {
    this.put("approval", a.id, a.tenantId, a);
  }
  getApproval(id: string): ApprovalRequest | undefined {
    return this.getById("approval", id);
  }
  listApprovals(tenantId: string, status?: ApprovalRequest["status"]): ApprovalRequest[] {
    const all = this.listByTenant<ApprovalRequest>("approval", tenantId);
    return status ? all.filter((a) => a.status === status) : all;
  }

  // -- one-time jtis ----------------------------------------------------------

  /** Returns true when the jti was fresh (and is now consumed). */
  consumeJti(jti: string, kind: "proof" | "assertion" | "token", ttlSeconds: number): boolean {
    this.db.prepare("DELETE FROM used_jtis WHERE expires_at < ?").run(Date.now());
    try {
      this.db
        .prepare("INSERT INTO used_jtis (jti, kind, expires_at) VALUES (?, ?, ?)")
        .run(jti, kind, Date.now() + ttlSeconds * 1000);
      return true;
    } catch {
      return false;
    }
  }

  // -- secrets ----------------------------------------------------------------

  putSecret(ref: string, sealed: SealedSecret): void {
    this.db
      .prepare(
        "INSERT INTO secrets (ref, iv, ct, tag) VALUES (?, ?, ?, ?) ON CONFLICT(ref) DO UPDATE SET iv = excluded.iv, ct = excluded.ct, tag = excluded.tag",
      )
      .run(ref, sealed.iv, sealed.ct, sealed.tag);
  }
  getSecret(ref: string): SealedSecret | undefined {
    return this.db.prepare("SELECT iv, ct, tag FROM secrets WHERE ref = ?").get(ref) as
      | SealedSecret
      | undefined;
  }

  // -- audit --------------------------------------------------------------------

  appendAudit(record: AuditRecord): void {
    this.db
      .prepare("INSERT INTO audit (seq, tenant_id, json) VALUES (?, ?, ?)")
      .run(record.seq, record.tenantId, JSON.stringify(record));
  }
  lastAudit(): AuditRecord | undefined {
    const row = this.db.prepare("SELECT json FROM audit ORDER BY seq DESC LIMIT 1").get() as
      | { json: string }
      | undefined;
    return row ? (JSON.parse(row.json) as AuditRecord) : undefined;
  }
  listAudit(tenantId?: string): AuditRecord[] {
    const rows = (
      tenantId
        ? this.db.prepare("SELECT json FROM audit WHERE tenant_id = ? ORDER BY seq").all(tenantId)
        : this.db.prepare("SELECT json FROM audit ORDER BY seq").all()
    ) as { json: string }[];
    return rows.map((r) => JSON.parse(r.json) as AuditRecord);
  }

  close(): void {
    this.db.close();
  }
}
