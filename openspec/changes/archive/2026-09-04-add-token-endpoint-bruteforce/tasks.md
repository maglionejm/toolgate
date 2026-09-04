## 1. Limiting
- [x] 1.1 Failure-count backoff keyed by agent id (+source), reset on success
- [x] 1.2 Trusted-proxy config + source extraction helper (shared with gate limits)

## 2. Telemetry
- [x] 2.1 Failure counters by reason class; healthz detail block
- [x] 2.2 Hourly audit summary record (source=operator? new source 'system' — design note)

## 3. Hardening & docs
- [x] 3.1 Uniform failure envelope/timing review on the token route
- [x] 3.2 DEPLOYMENT (proxy config), SECURITY (T-row update), tests incl. XFF spoofing and backoff reset
