## 1. Interface split
- [x] 1.1 Extract Store interface; move SQLite impl behind it; DSN-based factory in context
- [x] 1.2 Row-version column + version-checked doc cache (or per-request cache in PG mode) — shipped as: doc cache disabled in PG mode (every read hits the database; coherence by construction)

## 2. Postgres implementation
- [x] 2.1 Schema + asyncpg/psycopg driver decision (sync parity vs async store refactor — design.md) — decision: psycopg3 sync behind a connection facade, keeping the Store surface unchanged
- [x] 2.2 Atomic ops: budget conditional UPDATE, approval claim transition, jti unique inserts
- [x] 2.3 Shared fixed-window rate-limit table; limiter selection by backend

## 3. Migration & ops
- [x] 3.1 `toolgate migrate --from sqlite.db --to postgres://…` with chain re-verification
- [x] 3.2 DEPLOYMENT.md: drop the max-instances=1 constraint for PG; compose profile with postgres

## 4. Verification
- [x] 4.1 CI job: postgres service, full suite + two-instance concurrency tests (races, replay, revocation coherence)
