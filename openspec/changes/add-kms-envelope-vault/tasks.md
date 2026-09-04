## 1. Core
- [ ] 1.1 Versioned blob format {v, kekId, wrappedDek, iv, ct}
- [ ] 1.2 Provider interface (wrap/unwrap/kek-id) + env provider parity
- [ ] 1.3 GCP KMS provider (google-cloud-kms extra), AWS KMS provider (boto3 extra)

## 2. Lifecycle
- [ ] 2.1 Boot wiring + fail-closed rules (dev_mode interaction)
- [ ] 2.2 `toolgate vault rotate-kek` + `toolgate vault migrate` (owner role, audited)

## 3. Verification & docs
- [ ] 3.1 Tests: seal/open per provider (KMS faked), rotation window, migration, KMS-down fail-closed
- [ ] 3.2 DEPLOYMENT.md (per-cloud setup), OPERATIONS.md R5 update, SECURITY.md gap register update
