import json
import sqlite3
import time
from typing import Any

from pydantic import BaseModel

from toolgate.core import (
    AgentIdentity,
    ApprovalRequest,
    AuditRecord,
    Budget,
    DelegationGrant,
    Policy,
    Tenant,
    Upstream,
    User,
)

from .vault import SealedSecret

_SCHEMA = """
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
    ct TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    json TEXT NOT NULL
);
"""


class Store:
    """Single-file SQLite persistence. Entities are stored as JSON documents
    with the columns needed for lookups; swapping this class for Postgres is
    the designated scale path (issue #16)."""

    def __init__(self, path: str) -> None:
        # autocommit; check_same_thread off so the demo can serve from threads.
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode = WAL;")
        self.db.executescript(_SCHEMA)
        # Parsed-document cache: pydantic validation dominates read cost on the
        # gate hot path. Invalidated on every write; callers get shallow copies
        # so top-level mutation cannot poison the cache.
        self._doc_cache: dict[str, Any] = {}
        self._last_jti_prune = 0.0

    # -- settings -------------------------------------------------------------

    def get_setting(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_setting(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # -- generic entities -------------------------------------------------------

    def _put(self, kind: str, entity_id: str, tenant_id: str | None, doc: Any) -> None:
        self._doc_cache.pop(entity_id, None)
        self.db.execute(
            "INSERT INTO entities (id, kind, tenant_id, json) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            (entity_id, kind, tenant_id, json.dumps(doc)),
        )

    def _get_model[M: BaseModel](self, kind: str, entity_id: str, model: type[M]) -> M | None:
        cached = self._doc_cache.get(entity_id)
        if cached is not None:
            return cached.model_copy()
        doc = self._get(kind, entity_id)
        if doc is None:
            return None
        validated = model.model_validate(doc)
        self._doc_cache[entity_id] = validated
        return validated.model_copy()

    def _get(self, kind: str, entity_id: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT json FROM entities WHERE id = ? AND kind = ?", (entity_id, kind)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def _list(self, kind: str, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT json FROM entities WHERE kind = ? AND tenant_id = ? ORDER BY id",
            (kind, tenant_id),
        ).fetchall()
        return [json.loads(r[0]) for r in rows]

    # -- typed accessors ----------------------------------------------------------

    def put_tenant(self, t: Tenant) -> None:
        self._put("tenant", t.id, t.id, t.model_dump(mode="json", exclude_none=True))

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self._get_model("tenant", tenant_id, Tenant)

    def put_user(self, u: User) -> None:
        self._put("user", u.id, u.tenantId, u.model_dump(mode="json", exclude_none=True))

    def get_user(self, user_id: str) -> User | None:
        return self._get_model("user", user_id, User)

    def put_agent(self, a: AgentIdentity) -> None:
        self._put("agent", a.id, a.tenantId, a.model_dump(mode="json", exclude_none=True))

    def get_agent(self, agent_id: str) -> AgentIdentity | None:
        return self._get_model("agent", agent_id, AgentIdentity)

    def put_upstream(self, u: Upstream) -> None:
        self._put("upstream", u.id, u.tenantId, u.model_dump(mode="json", exclude_none=True))

    def find_upstream_by_name(self, tenant_id: str, name: str) -> Upstream | None:
        # Runs on every gate call: resolve the id with a single indexed +
        # json_extract query, then reuse the parsed-document cache.
        row = self.db.execute(
            "SELECT id FROM entities WHERE kind = 'upstream' AND tenant_id = ? "
            "AND json_extract(json, '$.name') = ?",
            (tenant_id, name),
        ).fetchone()
        return self._get_model("upstream", row[0], Upstream) if row else None

    def put_policy(self, p: Policy) -> None:
        self._put("policy", p.id, p.tenantId, p.model_dump(mode="json", exclude_none=True))

    def get_policy(self, policy_id: str) -> Policy | None:
        return self._get_model("policy", policy_id, Policy)

    def put_grant(self, g: DelegationGrant) -> None:
        self._put("grant", g.id, g.tenantId, g.model_dump(mode="json", exclude_none=True))
        self.db.execute(
            "INSERT INTO grant_budgets (grant_id, max_units, spent_units) VALUES (?, ?, ?) "
            "ON CONFLICT(grant_id) DO UPDATE SET max_units = excluded.max_units",
            (g.id, g.budget.maxUnits, g.budget.spentUnits),
        )

    def get_grant(self, grant_id: str) -> DelegationGrant | None:
        grant = self._get_model("grant", grant_id, DelegationGrant)
        if not grant:
            return None
        # Budget lives in its own row (atomic charging); merge the live value.
        row = self.db.execute(
            "SELECT max_units, spent_units FROM grant_budgets WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        if row:
            grant.budget = Budget(maxUnits=row[0], spentUnits=row[1])
        return grant

    def charge_budget(self, grant_id: str, cost_units: int) -> bool:
        """Atomic conditional charge; False when the budget cannot cover the cost."""
        cursor = self.db.execute(
            "UPDATE grant_budgets SET spent_units = spent_units + ? "
            "WHERE grant_id = ? AND spent_units + ? <= max_units",
            (cost_units, grant_id, cost_units),
        )
        return cursor.rowcount == 1

    def put_approval(self, a: ApprovalRequest) -> None:
        self._put("approval", a.id, a.tenantId, a.model_dump(mode="json", exclude_none=True))

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        return self._get_model("approval", approval_id, ApprovalRequest)

    def list_approvals(self, tenant_id: str, status: str | None = None) -> list[ApprovalRequest]:
        approvals = [ApprovalRequest.model_validate(d) for d in self._list("approval", tenant_id)]
        return [a for a in approvals if status is None or a.status == status]

    # -- one-time jtis --------------------------------------------------------------

    def consume_jti(self, jti: str, kind: str, ttl_seconds: int) -> bool:
        """True when the jti was fresh (and is now consumed)."""
        now = time.time()
        now_ms = int(now * 1000)
        # Pruning is maintenance, not correctness (expiry is enforced by the
        # proof/assertion time checks) — throttle it to one sweep per minute
        # instead of a delete on every call.
        if now - self._last_jti_prune > 60:
            self.db.execute("DELETE FROM used_jtis WHERE expires_at < ?", (now_ms,))
            self._last_jti_prune = now
        try:
            self.db.execute(
                "INSERT INTO used_jtis (jti, kind, expires_at) VALUES (?, ?, ?)",
                (jti, kind, now_ms + ttl_seconds * 1000),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    # -- secrets ----------------------------------------------------------------------

    def put_secret(self, ref: str, sealed: SealedSecret) -> None:
        self.db.execute(
            "INSERT INTO secrets (ref, iv, ct) VALUES (?, ?, ?) "
            "ON CONFLICT(ref) DO UPDATE SET iv = excluded.iv, ct = excluded.ct",
            (ref, sealed.iv, sealed.ct),
        )

    def get_secret(self, ref: str) -> SealedSecret | None:
        row = self.db.execute("SELECT iv, ct FROM secrets WHERE ref = ?", (ref,)).fetchone()
        return SealedSecret(iv=row[0], ct=row[1]) if row else None

    # -- audit -------------------------------------------------------------------------

    def append_audit(self, record: AuditRecord) -> None:
        doc = json.dumps(record.model_dump(mode="json", exclude_none=True))
        self.db.execute(
            "INSERT INTO audit (seq, tenant_id, json) VALUES (?, ?, ?)",
            (record.seq, record.tenantId, doc),
        )

    def last_audit(self) -> AuditRecord | None:
        row = self.db.execute("SELECT json FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return AuditRecord.model_validate(json.loads(row[0])) if row else None

    def list_audit(self, tenant_id: str | None = None) -> list[AuditRecord]:
        if tenant_id:
            rows = self.db.execute(
                "SELECT json FROM audit WHERE tenant_id = ? ORDER BY seq", (tenant_id,)
            ).fetchall()
        else:
            rows = self.db.execute("SELECT json FROM audit ORDER BY seq").fetchall()
        return [AuditRecord.model_validate(json.loads(r[0])) for r in rows]

    def close(self) -> None:
        self.db.close()
