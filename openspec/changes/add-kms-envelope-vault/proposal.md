# KMS envelope encryption for the vault

## Why
GitHub issue: #8. Upstream secrets are sealed with AES-256-GCM under a single env-var master key: whoever reads the environment (or a dev-mode database) holds every credential, and rotation requires re-sealing everything manually. Production custody needs keys that never leave a KMS.

## What Changes
- Envelope encryption: per-secret data keys (DEK) wrapped by a KMS-held key-encryption key (KEK); ciphertext stores the wrapped DEK alongside the sealed payload.
- Provider abstraction with three implementations: `env` (current behavior, dev), `gcp-kms` (first cloud target), `aws-kms` (second).
- KEK rotation: re-wrap DEKs without ever exposing plaintext secrets; vault format versioned for migration from v1 blobs.
- Fail-closed posture and audited vault operations.

## Impact
- Affected specs: vault (new)
- Affected code: server/vault.py, server/store.py (blob format), context boot, DEPLOYMENT/OPERATIONS docs
