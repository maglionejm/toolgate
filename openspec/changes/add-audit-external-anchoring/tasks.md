## 1. Rekor sink
- [ ] 1.1 Rekor client (hashedrekord over checkpoint canonical bytes) + persisted proofs
- [ ] 1.2 Extend Checkpoint model/meta with anchor evidence (additive, hash-stable)

## 2. Verification
- [ ] 2.1 Inclusion/consistency validation in core verify (offline, trust root pinned)
- [ ] 2.2 CLI: `audit verify --rekor [--trust-root file]`; bundle format v2

## 3. Retention
- [ ] 3.1 Export job (S3/GCS providers) with object-lock config + manifest index
- [ ] 3.2 Failure visibility: healthz anchoring status, consecutive-failure counter

## 4. Docs & tests
- [ ] 4.1 OPERATIONS R7 rewrite (proof-grade procedure), SECURITY matrix T14 upgrade
- [ ] 4.2 Tests with a faked Rekor (anchor, verify, outage, post-compromise rewrite detection)
