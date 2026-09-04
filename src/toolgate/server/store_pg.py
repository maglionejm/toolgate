"""Postgres store (#16): the same Store surface backed by psycopg, selected by
DSN (`TOOLGATE_DB=postgres://…`). The four correctness properties that SQLite
enforced per-process — atomic budget charging, one-time jtis, the approval
executing-claim, and rate limiting — become database-enforced, so they hold for
any number of server instances.

Implementation note: the SQLite Store's SQL is deliberately portable; this
class inherits it through a thin connection facade that adapts placeholders
(? -> %s) and overrides only the divergent pieces (schema DDL, JSON path
operators, unique-violation class, and the parsed-document cache, which is
disabled here because a per-process cache cannot see writes on other
instances)."""

import json
import time
from typing import Any

from pydantic import BaseModel

from .store import Store

_PG_SCHEMA = """
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
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (jti, kind)
);
CREATE TABLE IF NOT EXISTS secrets (
    ref TEXT PRIMARY KEY,
    iv TEXT NOT NULL,
    ct TEXT NOT NULL,
    v INTEGER NOT NULL DEFAULT 1,
    kek_id TEXT,
    wrapped_dek TEXT
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
    expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_failures (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    until_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    status TEXT NOT NULL,
    next_attempt_ms BIGINT NOT NULL,
    json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(status, next_attempt_ms);
CREATE INDEX IF NOT EXISTS idx_deliveries_approval ON deliveries(approval_id);
CREATE TABLE IF NOT EXISTS link_tokens (
    token_hash TEXT PRIMARY KEY,
    json TEXT NOT NULL,
    consumed_at TEXT
);
CREATE TABLE IF NOT EXISTS rate_windows (
    key TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (key, window_start)
);
"""


class _PgConnection:
    """sqlite3-shaped facade over a psycopg connection: qmark placeholders,
    autocommit (each statement is its own transaction, matching the SQLite
    store's isolation model), `execute` returning a cursor."""

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
        except ImportError as err:
            raise RuntimeError(
                "psycopg is required for the Postgres store: "
                "pip install 'toolgate-io[postgres]'"
            ) from err
        self._conn = psycopg.connect(dsn, autocommit=True)

    def execute(self, sql: str, params: tuple = ()) -> Any:
        return self._conn.execute(sql.replace("?", "%s"), params)  # type: ignore[arg-type]

    def close(self) -> None:
        self._conn.close()


def is_postgres_dsn(target: str) -> bool:
    return target.startswith(("postgres://", "postgresql://"))


def open_store(target: str) -> Store:
    """Backend factory: a postgres DSN activates the Postgres store; anything
    else (file path, :memory:) keeps single-node SQLite."""
    if is_postgres_dsn(target):
        return PostgresStore(target)
    return Store(target)


class PostgresStore(Store):
    def __init__(self, dsn: str) -> None:  # noqa: D107 - contract documented on Store
        self.db = _PgConnection(dsn)  # type: ignore[assignment]
        for statement in _PG_SCHEMA.strip().split(";"):
            if statement.strip():
                self.db.execute(statement)
        # No parsed-document cache in multi-instance mode: another instance's
        # write (revocation, operator disable, policy change) must be visible
        # on the very next read here.
        self._doc_cache = {}
        self._last_jti_prune = 0.0
        self._last_approval_prune = 0.0

    # -- cache disabled: always parse fresh --------------------------------------------

    def _get_model[M: BaseModel](self, kind: str, entity_id: str, model: type[M]) -> M | None:
        doc = self._get(kind, entity_id)
        return model.model_validate(doc) if doc is not None else None

    # -- JSON path dialect --------------------------------------------------------------

    def claim_approval_for_execution(self, approval_id: str) -> bool:
        cursor = self.db.execute(
            "UPDATE entities SET json = "
            "jsonb_set(json::jsonb, '{status}', '\"executing\"')::text "
            "WHERE id = ? AND kind = 'approval' "
            "AND json::jsonb->>'status' = 'approved'",
            (approval_id,),
        )
        return cursor.rowcount == 1

    def revert_approval_claim(self, approval_id: str) -> None:
        self.db.execute(
            "UPDATE entities SET json = "
            "jsonb_set(json::jsonb, '{status}', '\"approved\"')::text "
            "WHERE id = ? AND kind = 'approval' "
            "AND json::jsonb->>'status' = 'executing'",
            (approval_id,),
        )

    def prune_approvals(self) -> None:
        now = time.time()
        if now - self._last_approval_prune <= 60:
            return
        self._last_approval_prune = now
        from datetime import UTC, datetime

        self.db.execute(
            "DELETE FROM entities WHERE kind = 'approval' AND ("
            "json::jsonb->>'status' IN ('executed', 'denied', 'expired') "
            "OR json::jsonb->>'expiresAt' < ?)",
            (datetime.now(UTC).isoformat(),),
        )

    def find_operator_by_key_hash(self, key_hash: str) -> Any:
        row = self.db.execute(
            "SELECT id FROM entities WHERE kind = 'operator' "
            "AND json::jsonb->>'keyHash' = ?",
            (key_hash,),
        ).fetchone()
        return self.get_operator(row[0]) if row else None

    # -- unique-violation dialect --------------------------------------------------------

    def consume_jti(self, jti: str, kind: str, ttl_seconds: int) -> bool:
        import psycopg

        now = time.time()
        now_ms = int(now * 1000)
        if now - self._last_jti_prune > 60:
            self.db.execute("DELETE FROM used_jtis WHERE expires_at < ?", (now_ms,))
            self._last_jti_prune = now
        try:
            self.db.execute(
                "INSERT INTO used_jtis (jti, kind, expires_at) VALUES (?, ?, ?)",
                (jti, kind, now_ms + ttl_seconds * 1000),
            )
            return True
        except psycopg.errors.UniqueViolation:
            return False

    def append_audit(self, record: Any) -> bool:
        doc = json.dumps(record.model_dump(mode="json", exclude_none=True))
        cursor = self.db.execute(
            "INSERT INTO audit (seq, tenant_id, json) VALUES (?, ?, ?) "
            "ON CONFLICT (seq) DO NOTHING",
            (record.seq, record.tenantId, doc),
        )
        return cursor.rowcount == 1

    # -- shared rate limiting -------------------------------------------------------------

    def rate_window_bump(self, key: str, window_start: int) -> int:
        """Atomically count an event in the fixed window; returns the new count.
        Shared across every instance pointing at this database."""
        row = self.db.execute(
            "INSERT INTO rate_windows (key, window_start, count) VALUES (?, ?, 1) "
            "ON CONFLICT (key, window_start) DO UPDATE "
            "SET count = rate_windows.count + 1 RETURNING count",
            (key, window_start),
        ).fetchone()
        # Opportunistic cleanup of stale windows (maintenance, not correctness).
        self.db.execute("DELETE FROM rate_windows WHERE window_start < ?", (window_start - 2,))
        return int(row[0])


# ---------------------------------------------------------------------------
# SQLite -> Postgres migration (verbatim copy; the audit chain must verify
# identically on the target).
# ---------------------------------------------------------------------------

_TABLES: dict[str, list[str]] = {
    "settings": ["key", "value"],
    "entities": ["id", "kind", "tenant_id", "json"],
    "grant_budgets": ["grant_id", "max_units", "spent_units"],
    "used_jtis": ["jti", "kind", "expires_at"],
    "secrets": ["ref", "iv", "ct", "v", "kek_id", "wrapped_dek"],
    "audit": ["seq", "tenant_id", "json"],
    "checkpoints": ["seq", "json"],
    "txn_taint": ["txn", "expires_at"],
    "auth_failures": ["key", "count", "until_ms"],
    "deliveries": ["id", "tenant_id", "approval_id", "status", "next_attempt_ms", "json"],
    "link_tokens": ["token_hash", "json", "consumed_at"],
}


def migrate_sqlite_to_postgres(sqlite_path: str, dsn: str) -> dict[str, Any]:
    """Copy every table verbatim, then re-verify the audit chain on the target
    against the migrated gate keyset. Returns per-table counts + verification."""
    from toolgate.core import verify_audit_chain

    src = Store(sqlite_path)
    dst = PostgresStore(dsn)
    counts: dict[str, int] = {}
    for table, columns in _TABLES.items():
        rows = src.db.execute(f"SELECT {', '.join(columns)} FROM {table}").fetchall()  # noqa: S608
        placeholders = ", ".join("?" for _ in columns)
        for row in rows:
            dst.db.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "  # noqa: S608
                "ON CONFLICT DO NOTHING",
                tuple(row),
            )
        counts[table] = len(rows)

    keyset_raw = dst.get_setting("keyset:gate")
    jwks = (
        {d["kid"]: d["public_jwk"] for d in json.loads(keyset_raw)} if keyset_raw else {}
    )
    verification = verify_audit_chain(dst.list_audit(), jwks)
    return {
        "tables": counts,
        "records": counts.get("audit", 0),
        "valid": verification.valid,
        "length": verification.length,
    }
