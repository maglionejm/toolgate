## 1. Interface split
- [ ] 1.1 Extract Store interface; move SQLite impl behind it; DSN-based factory in context
- [ ] 1.2 Row-version column + version-checked doc cache (or per-request cache in PG mode)

## 2. Postgres implementation
- [ ] 2.1 Schema + asyncpg/psycopg driver decision (sync parity vs async store refactor — design.md)
- [ ] 2.2 Atomic ops: budget conditional UPDATE, approval claim transition, jti unique inserts
- [ ] 2.3 Shared fixed-window rate-limit table; limiter selection by backend

## 3. Migration & ops
- [ ] 3.1 `toolgate migrate --from sqlite.db --to postgres://…` with chain re-verification
- [ ] 3.2 DEPLOYMENT.md: drop the max-instances=1 constraint for PG; compose profile with postgres

## 4. Verification
- [ ] 4.1 CI job: postgres service, full suite + two-instance concurrency tests (races, replay, revocation coherence)
