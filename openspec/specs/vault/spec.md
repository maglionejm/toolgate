# vault Specification

## Purpose
TBD - created by archiving change add-kms-envelope-vault. Update Purpose after archive.

## Requirements

### Requirement: Envelope encryption
The vault SHALL seal each secret with a unique data key and store only the KMS-wrapped data key with the ciphertext; plaintext data keys SHALL exist only transiently in memory during seal/open.

#### Scenario: Seal under KMS
- **WHEN** an upstream credential is registered with provider `gcp-kms`
- **THEN** the stored blob contains {wrapped DEK, iv, ciphertext, kek id, format version} and no material decryptable without the KMS

### Requirement: Provider abstraction
Vault configuration SHALL select a provider (`env`, `gcp-kms`, `aws-kms`) at boot; the `env` provider SHALL preserve current behavior for development, and production boot (dev_mode=False) SHALL refuse the `env` provider unless explicitly overridden.

#### Scenario: Fail closed without KMS
- **WHEN** the server boots with provider `gcp-kms` and the KMS is unreachable
- **THEN** boot fails with a clear error; no fallback provider is silently substituted

### Requirement: KEK rotation without exposure
Rotating the KEK SHALL re-wrap every stored DEK via the KMS and SHALL NOT decrypt any secret payload in the process; both KEK versions SHALL be usable during the rotation window.

#### Scenario: Rotate KEK
- **WHEN** an owner runs `toolgate vault rotate-kek`
- **THEN** all blobs reference the new KEK id afterwards and secrets open successfully; the operation is recorded in the audit chain

### Requirement: Format migration
Opening a v1 (master-key) blob under a KMS provider SHALL transparently re-seal it as v2 on next write, and a migration command SHALL bulk-convert.

#### Scenario: Bulk migration
- **WHEN** `toolgate vault migrate` runs against a v1 store with a configured KMS
- **THEN** every secret is re-sealed as v2 and a summary (count, failures) is reported
