# persistence Specification

## Purpose
TBD - created by archiving change add-postgres-scale-out. Update Purpose after archive.

## Requirements

### Requirement: Backend selection by DSN
The server SHALL select the store backend from `TOOLGATE_DB`: a `postgres://` DSN activates the Postgres store; a file path (or `:memory:`) keeps SQLite. Behavior and wire formats SHALL be identical across backends.

#### Scenario: Boot with Postgres
- **WHEN** the server boots with a postgres DSN
- **THEN** all endpoints operate with unchanged semantics and the full test suite passes against it

### Requirement: Exactly-once across instances
Budget charges, approval execution claims, and one-time jtis SHALL be enforced by database-side atomic operations such that the guarantees hold for any number of concurrent server instances.

#### Scenario: Cross-instance budget race
- **WHEN** two server instances race the final budget unit
- **THEN** exactly one call executes and one charge is recorded

#### Scenario: Cross-instance proof replay
- **WHEN** a PoP proof accepted by instance A is replayed to instance B
- **THEN** instance B rejects it with TG_PROOF_INVALID

### Requirement: Shared rate limiting
When Postgres is active, token-endpoint and gate rate limits SHALL be enforced against shared state so N instances collectively honor the configured ceilings.

#### Scenario: Split traffic
- **WHEN** a grant's calls are load-balanced across two instances
- **THEN** the combined rate cannot exceed the configured per-grant limit

### Requirement: Cache coherence
Cross-instance reads SHALL never serve stale security-relevant state: grant revocation, operator disablement, and policy changes SHALL take effect on the next call regardless of which instance handled the write.

#### Scenario: Revoke on A, call on B
- **WHEN** a grant is revoked via instance A and the agent calls instance B
- **THEN** instance B refuses with TG_REVOKED

### Requirement: Migration
A `toolgate migrate` command SHALL copy a SQLite store (entities, budgets, secrets, audit chain, checkpoints) into Postgres verbatim, preserving hash-chain verifiability.

#### Scenario: Verified migration
- **WHEN** migration completes
- **THEN** `audit verify` on the Postgres store reports the same length and validity as the source
