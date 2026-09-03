# ADR 0005: Reference implementation moves to Python

**Status**: accepted · 2026-09-03 · supersedes the runtime half of ADR 0003

## Context

The MVP was built in TypeScript (ADR 0003). A dedicated research pass (Sept 2026) compared TS vs Python for this product and favored keeping TS on technical grounds — most decisively, Node's `jose` covers EdDSA/JWK-thumbprint/DPoP today while Python has no maintained DPoP implementation (authlib #315 open since 2021). The same research found that (a) the control-plane language is commercially invisible, (b) the agent-backend majority (LangGraph ~64M downloads/month) lives in Python, and (c) polyglot server-plus-many-SDKs is the industry norm.

## Decision

Founder decision: the reference implementation is Python — team and ecosystem alignment outweigh the library-maturity argument. Stack: Python ≥3.12, FastAPI + uvicorn, pydantic v2, `jwcrypto` + `cryptography`, stdlib `sqlite3`, `httpx`, `uv` + `ruff` + `pytest` tooling.

Consequences accepted knowingly:

1. **PoP proofs are hand-implemented** (`toolgate/core/assertion.py`): custom `tg-pop+jwt` JWS following RFC 9449's model (embedded JWK, thumbprint binding, htm/htu/ath, one-time jti, freshness window). This code carries security-critical responsibility that `jose` provided for free in Node; it is covered by dedicated theft/replay/rebind tests and is a priority target for external review (red-team issue #9).
2. **Wire and storage formats are unchanged** (camelCase fields, same endpoints, same token claims), so the port is invisible to API clients and existing documentation.
3. The TypeScript implementation (including its SDK) was removed from the working tree at commit history point `6424941`; a TS SDK will be rebuilt against the Python server for the embedded/browser thesis (tracked in the backlog).

## Consequences

- `pip install toolgate` becomes the native story for the LangGraph/CrewAI/PydanticAI majority.
- Test parity maintained: 39 tests (25 core, 10 server integration, 4 SDK).
- Cloud Run deployment now ships a Python image; cold-start/footprint deltas accepted.
