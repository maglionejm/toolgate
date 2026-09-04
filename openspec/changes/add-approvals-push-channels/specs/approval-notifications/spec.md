# approval-notifications Specification

## ADDED Requirements

### Requirement: Channel configuration
Tenants SHALL configure zero or more notification channels (webhook, slack, email); configuration is owner-gated and secrets (webhook signing preferences, Slack tokens) are sealed in the vault.

#### Scenario: Configure webhook
- **WHEN** an owner adds a webhook channel
- **THEN** parked approvals for that tenant trigger a delivery to it

### Requirement: Signed, retried webhook delivery
Webhook payloads SHALL be signed (detached JWS by the gate key, kid included) and delivered with bounded retries and exponential backoff; deliveries SHALL be recorded with status.

#### Scenario: Endpoint down
- **WHEN** the first delivery attempt fails
- **THEN** retries follow with backoff and the delivery record shows the final status; the approval itself is unaffected

### Requirement: Slack decisions with operator attribution
Slack approve/deny actions SHALL verify Slack request signatures, map the Slack user to a bound operator (unbound users are refused with guidance), and record the decision identically to a console decision — including the exact-args binding.

#### Scenario: Slack approve
- **WHEN** a bound approver clicks Approve in Slack
- **THEN** the approval flips to approved with decidedBy = their operator id and an ops audit record is appended

### Requirement: Email magic links
Email decisions SHALL use single-use tokens bound to {approval id, args hash, decision} with expiry no longer than the approval's own expiry; a consumed or expired link SHALL decide nothing.

#### Scenario: Replayed link
- **WHEN** an approve link is opened a second time
- **THEN** no state changes and the response says the link was already used

### Requirement: Fan-out completeness
Every parked approval SHALL fan out to all configured channels within 5 seconds of parking, and expiry/decision SHALL cancel outstanding actionable surfaces where the channel supports it (Slack message update).

#### Scenario: Decided elsewhere
- **WHEN** an approval is decided in the console after Slack delivery
- **THEN** the Slack message updates to reflect the decision and its buttons deactivate
