# Postgres store and multi-instance correctness

## Why
GitHub issue: #16. Four correctness properties currently depend on single-process SQLite: atomic budget charging, single-use jtis (proofs/assertions), the approval executing-claim, and rate limiting (in-memory). Any second gate instance silently breaks exactly-once guarantees. Postgres is the designated scale path (ADR 0003) — this change makes the guarantees hold for N instances.

## What Changes
- `Store` gains a Postgres implementation behind the same interface, selected by DSN (`TOOLGATE_DB=postgres://…`); SQLite remains the single-node default.
- Concurrency-bearing operations move to database-enforced primitives: conditional UPDATEs for budget and approval claims, INSERT-on-conflict for jtis, and a shared rate-limit table (fixed-window per key) replacing the in-process limiter when Postgres is active.
- The parsed-document cache becomes correctness-safe across instances (row-version column; cache validated by version).
- Migration command (sqlite → postgres) and a CI job running the full suite plus concurrency tests against a real Postgres service with two app instances.

## Impact
- Affected specs: persistence (new)
- Affected code: server/store.py (split interface/impls), context, ratelimit, deployment docs, CI
