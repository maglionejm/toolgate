# audit-anchoring Specification

## ADDED Requirements

### Requirement: Rekor anchoring with stored proofs
When a Rekor sink is configured, each checkpoint SHALL be published to the transparency log and the returned {logIndex, inclusionProof, logId} SHALL be persisted with the checkpoint and included in audit bundles.

#### Scenario: Checkpoint anchored
- **WHEN** a checkpoint is cut with the Rekor sink enabled
- **THEN** the stored checkpoint carries its inclusion proof and the bundle export contains it

### Requirement: Externally verifiable history
Offline verification SHALL, given a bundle and Rekor trust root, validate checkpoint inclusion and log consistency such that a rewritten history is detected even if every current Toolgate key is attacker-controlled.

#### Scenario: Post-compromise rewrite
- **WHEN** an attacker with all gate keys re-signs a rewritten chain and new checkpoints
- **THEN** verification against previously anchored entries fails with a divergence report

### Requirement: WORM retention export
A retention job SHALL export bundles to object storage under a write-once policy with a configurable retention period (default ≥ 6 months) and a SHA-256 manifest per export.

#### Scenario: Retention export
- **WHEN** the export job runs
- **THEN** the bundle lands under an object-lock policy and the manifest is appended to an export index

### Requirement: Anchor failure visibility
Persistent anchoring failure (N consecutive checkpoints unanchored) SHALL be exposed via /healthz detail and a loud log line; verify output SHALL report the anchored/unanchored checkpoint ratio.

#### Scenario: Rekor outage
- **WHEN** three consecutive checkpoints fail to anchor
- **THEN** healthz reports degraded anchoring and operators can alert on it
