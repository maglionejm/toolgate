## 1. Core
- [x] 1.1 Versioned blob format {v, kekId, wrappedDek, iv, ct}
- [x] 1.2 Provider interface (wrap/unwrap/kek-id) + env provider parity
- [x] 1.3 GCP KMS provider (google-cloud-kms extra), AWS KMS provider (boto3 extra)

## 2. Lifecycle
- [x] 2.1 Boot wiring + fail-closed rules (dev_mode interaction)
- [x] 2.2 `toolgate vault rotate-kek` + `toolgate vault migrate` (owner role, audited)

## 3. Verification & docs
- [x] 3.1 Tests: seal/open per provider (KMS faked), rotation window, migration, KMS-down fail-closed
- [x] 3.2 DEPLOYMENT.md (per-cloud setup), OPERATIONS.md R5 update, SECURITY.md gap register update
