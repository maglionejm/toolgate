import contextlib
import json
import os
import sqlite3
import time
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from toolgate.core import (
    AgentIdentity,
    ApprovalRequest,
    AuditRecord,
    Budget,
    Checkpoint,
    DelegationGrant,
    Delivery,
    NotificationChannel,
    Operator,
    Policy,
    SlackBinding,
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
CREATE TABLE IF NOT EXISTS checkpoints (
    seq INTEGER PRIMARY KEY,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS txn_taint (
    txn TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_failures (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    until_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    status TEXT NOT NULL,
    next_attempt_ms INTEGER NOT NULL,
    json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(status, next_attempt_ms);
CREATE INDEX IF NOT EXISTS idx_deliveries_approval ON deliveries(approval_id);
CREATE TABLE IF NOT EXISTS link_tokens (
    token_hash TEXT PRIMARY KEY,
    json TEXT NOT NULL,
    consumed_at TEXT
);
"""


class Store:
    """Single-file SQLite persistence. Entities are stored as JSON documents
    with the columns needed for lookups; swapping this class for Postgres is
    the designated scale path (issue #16)."""

    def __init__(self, path: str) -> None:
        # autocommit; check_same_thread off so the demo can serve from threads.
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        # The DB holds the control/gate private keys, the admin key, and sealed
        # secrets — never let it be created world-readable on a shared host.
        if path != ":memory:" and os.path.exists(path):
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
        self.db.execute("PRAGMA journal_mode = WAL;")
        self.db.executescript(_SCHEMA)
        # Parsed-document cache: pydantic validation dominates read cost on the
        # gate hot path. Invalidated on every write; callers get shallow copies
        # so top-level mutation cannot poison the cache.
        self._doc_cache: dict[str, Any] = {}
        self._last_jti_prune = 0.0
        self._last_approval_prune = 0.0

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

    def list_tenants(self) -> list[Tenant]:
        rows = self.db.execute(
            "SELECT json FROM entities WHERE kind = 'tenant' ORDER BY id"
        ).fetchall()
        return [Tenant.model_validate(json.loads(r[0])) for r in rows]

    def list_users(self, tenant_id: str) -> list[User]:
        return [User.model_validate(d) for d in self._list("user", tenant_id)]

    def list_agents(self, tenant_id: str) -> list[AgentIdentity]:
        return [AgentIdentity.model_validate(d) for d in self._list("agent", tenant_id)]

    def list_upstreams(self, tenant_id: str) -> list[Upstream]:
        return [Upstream.model_validate(d) for d in self._list("upstream", tenant_id)]

    def list_policies(self, tenant_id: str) -> list[Policy]:
        return [Policy.model_validate(d) for d in self._list("policy", tenant_id)]

    def list_grants(self, tenant_id: str) -> list[DelegationGrant]:
        # get_grant merges the live budget row; accuracy over row count at CLI scale.
        grants = []
        for doc in self._list("grant", tenant_id):
            grant = self.get_grant(doc["id"])
            if grant:
                grants.append(grant)
        return grants

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

    def claim_approval_for_execution(self, approval_id: str) -> bool:
        """Atomically move an approval from 'approved' to 'executing'.

        Returns True only for the caller that won the transition; a second
        concurrent execute sees the row already past 'approved' and gets False.
        This is what closes the double-execution race — the status flip happens
        under SQLite's write lock, before the upstream call, not after it.
        """
        self._doc_cache.pop(approval_id, None)
        cursor = self.db.execute(
            "UPDATE entities SET json = json_set(json, '$.status', 'executing') "
            "WHERE id = ? AND kind = 'approval' "
            "AND json_extract(json, '$.status') = 'approved'",
            (approval_id,),
        )
        return cursor.rowcount == 1

    def revert_approval_claim(self, approval_id: str) -> None:
        """Release a claim ('executing' -> 'approved') if the upstream call
        failed, so a legitimate retry is still possible."""
        self._doc_cache.pop(approval_id, None)
        self.db.execute(
            "UPDATE entities SET json = json_set(json, '$.status', 'approved') "
            "WHERE id = ? AND kind = 'approval' "
            "AND json_extract(json, '$.status') = 'executing'",
            (approval_id,),
        )

    def list_approvals(self, tenant_id: str, status: str | None = None) -> list[ApprovalRequest]:
        approvals = [ApprovalRequest.model_validate(d) for d in self._list("approval", tenant_id)]
        return [a for a in approvals if status is None or a.status == status]

    def prune_approvals(self) -> None:
        """Drop terminal or long-expired approvals so the table cannot grow
        without bound. Throttled to once a minute; audit history is unaffected
        (executions are recorded in the signed audit chain, not here)."""
        now = time.time()
        if now - self._last_approval_prune <= 60:
            return
        self._last_approval_prune = now
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "DELETE FROM entities WHERE kind = 'approval' AND ("
            "json_extract(json, '$.status') IN ('executed', 'denied', 'expired') "
            "OR json_extract(json, '$.expiresAt') < ?)",
            (now_iso,),
        )

    # -- notification channels ---------------------------------------------------------

    def put_channel(self, c: NotificationChannel) -> None:
        self._put("channel", c.id, c.tenantId, c.model_dump(mode="json", exclude_none=True))

    def get_channel(self, channel_id: str) -> NotificationChannel | None:
        return self._get_model("channel", channel_id, NotificationChannel)

    def list_channels(self, tenant_id: str) -> list[NotificationChannel]:
        return [NotificationChannel.model_validate(d) for d in self._list("channel", tenant_id)]

    def delete_channel(self, channel_id: str) -> None:
        self._doc_cache.pop(channel_id, None)
        self.db.execute(
            "DELETE FROM entities WHERE id = ? AND kind = 'channel'", (channel_id,)
        )

    def put_slack_binding(self, b: SlackBinding) -> None:
        binding_id = f"slkb:{b.tenantId}:{b.slackUserId}"
        self._put("slack_binding", binding_id, b.tenantId, b.model_dump(mode="json"))

    def get_slack_binding(self, tenant_id: str, slack_user_id: str) -> SlackBinding | None:
        return self._get_model(
            "slack_binding", f"slkb:{tenant_id}:{slack_user_id}", SlackBinding
        )

    def list_slack_bindings(self, tenant_id: str) -> list[SlackBinding]:
        return [SlackBinding.model_validate(d) for d in self._list("slack_binding", tenant_id)]

    # -- deliveries --------------------------------------------------------------------

    def put_delivery(self, d: Delivery) -> None:
        next_ms = int(datetime.fromisoformat(d.nextAttemptAt).timestamp() * 1000)
        self.db.execute(
            "INSERT INTO deliveries (id, tenant_id, approval_id, status, next_attempt_ms, json) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET status = excluded.status, "
            "next_attempt_ms = excluded.next_attempt_ms, json = excluded.json",
            (
                d.id,
                d.tenantId,
                d.approvalId,
                d.status,
                next_ms,
                json.dumps(d.model_dump(mode="json", exclude_none=True)),
            ),
        )

    def due_deliveries(self, now_ms: int | None = None, limit: int = 50) -> list[Delivery]:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        rows = self.db.execute(
            "SELECT json FROM deliveries WHERE status = 'pending' AND next_attempt_ms <= ? "
            "ORDER BY next_attempt_ms LIMIT ?",
            (now_ms, limit),
        ).fetchall()
        return [Delivery.model_validate(json.loads(r[0])) for r in rows]

    def deliveries_for_approval(self, approval_id: str) -> list[Delivery]:
        rows = self.db.execute(
            "SELECT json FROM deliveries WHERE approval_id = ? ORDER BY id", (approval_id,)
        ).fetchall()
        return [Delivery.model_validate(json.loads(r[0])) for r in rows]

    # -- magic-link tokens -------------------------------------------------------------

    def put_link_token(self, token_hash: str, doc: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO link_tokens (token_hash, json, consumed_at) VALUES (?, ?, NULL)",
            (token_hash, json.dumps(doc)),
        )

    def consume_link_token(self, token_hash: str) -> tuple[str, dict[str, Any] | None]:
        """Atomically consume a magic link. Returns (status, doc) where status
        is 'ok' (consumed now), 'used' (already consumed), or 'unknown'."""
        row = self.db.execute(
            "SELECT json, consumed_at FROM link_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None:
            return "unknown", None
        if row[1] is not None:
            return "used", None
        cursor = self.db.execute(
            "UPDATE link_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL",
            (datetime.now(UTC).isoformat(), token_hash),
        )
        if cursor.rowcount != 1:
            return "used", None
        return "ok", json.loads(row[0])

    # -- auth failure backoff ----------------------------------------------------------

    def auth_failure_bump(self, key: str, threshold: int = 5, cap_seconds: int = 300) -> int:
        """Record a failed auth attempt; returns backoff seconds now in force
        (0 while under the threshold). Exponential from the threshold, capped."""
        now_ms = int(time.time() * 1000)
        row = self.db.execute(
            "SELECT count FROM auth_failures WHERE key = ?", (key,)
        ).fetchone()
        count = (row[0] if row else 0) + 1
        backoff = min(2 ** (count - threshold), cap_seconds) if count >= threshold else 0
        self.db.execute(
            "INSERT INTO auth_failures (key, count, until_ms) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET count = excluded.count, until_ms = excluded.until_ms",
            (key, count, now_ms + backoff * 1000),
        )
        return backoff

    def auth_backoff_remaining(self, key: str) -> int:
        row = self.db.execute(
            "SELECT until_ms FROM auth_failures WHERE key = ?", (key,)
        ).fetchone()
        if not row:
            return 0
        remaining_ms = row[0] - int(time.time() * 1000)
        return max(0, -(-remaining_ms // 1000))  # ceil to whole seconds

    def auth_failures_clear(self, key: str) -> None:
        self.db.execute("DELETE FROM auth_failures WHERE key = ?", (key,))

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

    # -- operators -------------------------------------------------------------------

    def put_operator(self, op: Operator) -> None:
        self._put("operator", op.id, None, op.model_dump(mode="json", exclude_none=True))

    def get_operator(self, operator_id: str) -> Operator | None:
        return self._get_model("operator", operator_id, Operator)

    def list_operators(self) -> list[Operator]:
        rows = self.db.execute(
            "SELECT json FROM entities WHERE kind = 'operator' ORDER BY id"
        ).fetchall()
        return [Operator.model_validate(json.loads(r[0])) for r in rows]

    def find_operator_by_key_hash(self, key_hash: str) -> Operator | None:
        row = self.db.execute(
            "SELECT id FROM entities WHERE kind = 'operator' "
            "AND json_extract(json, '$.keyHash') = ?",
            (key_hash,),
        ).fetchone()
        return self.get_operator(row[0]) if row else None

    # -- checkpoints ---------------------------------------------------------------

    def put_checkpoint(self, cp: Checkpoint) -> None:
        self.db.execute(
            "INSERT INTO checkpoints (seq, json) VALUES (?, ?) "
            "ON CONFLICT(seq) DO UPDATE SET json = excluded.json",
            (cp.seq, json.dumps(cp.model_dump(mode="json", exclude_none=True))),
        )

    def list_checkpoints(self) -> list[Checkpoint]:
        rows = self.db.execute("SELECT json FROM checkpoints ORDER BY seq").fetchall()
        return [Checkpoint.model_validate(json.loads(r[0])) for r in rows]

    # -- txn taint -------------------------------------------------------------------

    def mark_taint(self, keys: list[str], ttl_seconds: int = 86_400) -> None:
        """The task behind these keys consumed untrusted content. Keys are the
        txn id and (always, so operators can widen scope later without data
        loss) the grant scope key `grant:<id>`."""
        expires = int(time.time() * 1000) + ttl_seconds * 1000
        for key in keys:
            self.db.execute(
                "INSERT INTO txn_taint (txn, expires_at) VALUES (?, ?) "
                "ON CONFLICT(txn) DO UPDATE SET expires_at = excluded.expires_at",
                (key, expires),
            )

    def is_tainted(self, keys: list[str]) -> bool:
        now = int(time.time() * 1000)
        for key in keys:
            row = self.db.execute(
                "SELECT expires_at FROM txn_taint WHERE txn = ?", (key,)
            ).fetchone()
            if row and row[0] > now:
                return True
        return False

    def close(self) -> None:
        self.db.close()
