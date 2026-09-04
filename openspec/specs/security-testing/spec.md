# security-testing Specification

## Purpose
TBD - created by archiving change add-redteam-suite. Update Purpose after archive.

## Requirements

### Requirement: Adversarial suite in CI
The project SHALL maintain a red-team test suite under `tests/redteam/`, executed as a distinct CI job, where each module states its adversary model (what the attacker holds) and asserts the system's containment guarantees.

#### Scenario: CI gate
- **WHEN** any pull request runs CI
- **THEN** the red-team job executes and a successful attack fails the build

### Requirement: MCP stolen-token containment
The suite SHALL demonstrate that a capability token exfiltrated from an MCP client is bounded to its `authorization_details` ∩ policy ∩ remaining budget ∩ TTL, and dies immediately on grant revocation.

#### Scenario: Token theft via MCP
- **GIVEN** an attacker holding only a valid MCP-used capability token
- **WHEN** they call tools outside the delegation, or after revocation, or past the budget
- **THEN** every attempt is denied and audited

### Requirement: Rotation lineage integrity
The suite SHALL attempt forged handoffs (self-introduced kids, handoffs signed by untrusted kids, stripped handoff records) and verification SHALL reject each with the exact breakpoint.

#### Scenario: Self-introduced kid
- **WHEN** an attacker with a stolen current gate key appends a handoff naming their own kid and rewrites subsequent records
- **THEN** offline verification against anchored checkpoints detects the rewrite

### Requirement: Taint evasion resistance
The suite SHALL attempt to launder taint across transaction boundaries (fresh token per call, approval-then-execute splits) and document which evasions are structurally blocked versus accepted residual risk in docs/SECURITY.md.

#### Scenario: Txn splitting
- **WHEN** an agent reads untrusted content under txn A and requests the side effect under fresh txn B of the same grant
- **THEN** the outcome (blocked or accepted-risk) is asserted by a test and documented

### Requirement: Exactly-once under concurrency
The suite SHALL race budget charges and approval executions across concurrent requests and assert single execution and single charge.

#### Scenario: Last budget unit
- **WHEN** two concurrent calls contend for the final budget unit
- **THEN** exactly one executes and the other receives TG_BUDGET_EXCEEDED
