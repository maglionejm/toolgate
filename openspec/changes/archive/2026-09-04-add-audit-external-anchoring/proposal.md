# Transparency-log anchoring and WORM export for the audit chain

## Why
GitHub issue: #12. v0.4 shipped Merkle checkpoints and a webhook witness; what remains is proof-grade external anchoring: inclusion/consistency proofs from a public transparency log (Sigstore Rekor) and immutable retention (WORM) so the chain is evidentiary even against a fully compromised Toolgate.

## What Changes
- Rekor anchor sink: publish each checkpoint to Rekor, persist the log index + inclusion proof alongside the checkpoint.
- Offline verifier upgrade: `toolgate audit verify --file --rekor` validates inclusion and log consistency against Rekor's public key, not just local signatures.
- WORM export: scheduled bundle export to object storage with retention lock (S3 Object Lock / GCS retention), manifest-hashed.
- Anchor-failure alerting: anchoring is best-effort per checkpoint but persistent failure SHALL surface, not stay silent.

## Impact
- Affected specs: audit-anchoring (new)
- Affected code: server context (anchor sinks), core verify, CLI, OPERATIONS/SECURITY docs
