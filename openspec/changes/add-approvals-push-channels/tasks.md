## 1. Framework
- [ ] 1.1 Channel config model + store + owner endpoints; delivery records table
- [ ] 1.2 Notifier hooked into approval parking/decision/expiry transitions

## 2. Channels
- [ ] 2.1 Webhook: signed payload (detached JWS + kid), retry/backoff worker, replay-safe ids
- [ ] 2.2 Slack: app manifest docs, Block Kit renderer, signature verification, user↔operator binding, message updates
- [ ] 2.3 Email: SMTP config, magic-link tokens (single-use store), decision endpoints

## 3. Surfaces & docs
- [ ] 3.1 Console: channel settings + delivery status on approval cards; CLI channel commands
- [ ] 3.2 Docs: API, OPERATIONS R2 update, SECURITY (webhook signing, Slack sig verification, link threat notes)

## 4. Verification
- [ ] 4.1 Tests: fan-out timing, retries, Slack sig + binding refusal, magic-link single-use/expiry, attribution parity
