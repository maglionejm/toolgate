# Approvals v2: push channels (webhook, Slack, email magic link)

## Why
GitHub issue: #13. Approvals currently depend on someone watching the console or CLI. Approval latency is product-critical (it is the agent's blocked time), and unnoticed approvals expire. Decisions must reach humans where they already are.

## What Changes
- Channel framework with per-tenant configuration and per-channel delivery records.
- Webhook channel: signed payloads (gate key, same JWS discipline as audit), retries with backoff, replay-safe delivery ids.
- Slack channel: Block Kit message rendering the exact args; approve/deny actions mapped to operators via a Slack-user↔operator binding; interactivity endpoint verifies Slack signatures.
- Email channel: single-use, expiring magic links for approve/deny bound to the approval's args hash.
- All decisions keep operator attribution and land in the audit chain exactly like console decisions.

## Impact
- Affected specs: approval-notifications (new)
- Affected code: server (notifier + channel endpoints), store (channel config, deliveries), console (channel settings), docs
