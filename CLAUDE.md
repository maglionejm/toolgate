# CLAUDE.md

Toolgate is a capability control plane for embedded AI agents: agents hold zero
credentials; humans delegate bounded authority via grants; the gate enforces
policy/budget/approvals, injects real credentials server-side, and seals every
decision into a signed, anchorable audit chain. Python is the reference
implementation (ADR 0005). Current release: v0.5.0 (PyPI: `toolgate-io`,
import name `toolgate`; image: `ghcr.io/maglionejm/toolgate`).

## Commands

```bash
uv sync                                   # deps (extras: demo|langchain|postgres|gcp|aws|s3)
uv run ruff check src tests               # ALWAYS unpiped — piping through tail/grep swallows the exit code
uv run pytest -q                          # full suite incl. tests/redteam (adversarial)
uv run pytest -q --ignore=tests/redteam   # what the CI "checks" job runs
uv run pytest tests/test_postgres.py -q   # needs TOOLGATE_TEST_PG_DSN (postgres:16); skips otherwise
uv run toolgate demo                      # scripted six-act demo (offline, hermetic)
uv run toolgate demo --live               # real Claude model + injection act (ANTHROPIC_API_KEY, [demo] extra)
npx -y @fission-ai/openspec@latest validate --all
```

## Layout

| Path | What lives there |
| --- | --- |
| `src/toolgate/core/` | Tokens, assertions + PoP proofs, policy engine, audit chain + anchoring verification, types (camelCase wire format — do not snake_case; it is the persisted/protocol format) |
| `src/toolgate/server/` | `control.py` (control plane + token endpoint), `gate.py` (enforcement pipeline), `store.py` (SQLite) + `store_pg.py` (Postgres via qmark→%s facade), `vault.py` (KMS envelope), `notifier.py` (approval push channels), `broker.py` (per-user OAuth), `anchor.py` (Rekor sink), `hooks.py` (public Slack/magic-link/OAuth-callback endpoints), `approvals.py` (shared decide path) |
| `src/toolgate/sdk/` · `integrations/` · `cli/` · `console/static/` · `demo.py` / `demo_live.py` · `worm.py` | Agent client, framework adapters (`anthropic_tools`/`openai_tools`/`langchain_tools`), typer CLI, operator console SPA, demos, WORM exports |
| `openspec/specs/` | Living requirement baseline (archived change packages in `openspec/changes/archive/`) |
| `docs/` | QUICKSTART, ARCHITECTURE, SECURITY (threat matrix + red-team findings register), TOKEN-SPEC, DEPLOYMENT, OPERATIONS runbooks, reference/API + CLI, ADRs 0001–0009 |

## Workflow

- Every change goes through a GitHub issue (when one exists) and a PR — never
  commit directly to main. Squash-merge after all four CI jobs pass (checks,
  redteam, security, postgres). Auto-merge is not enabled; merge manually.
- Features are OpenSpec-driven: propose a change package under
  `openspec/changes/` (skills in `.claude/skills/openspec-*` drive the
  workflow), implement against its tasks.md, tick tasks, archive on ship.
- Releases are milestone/theme/security only — do not tag per-PR. A GitHub
  release auto-publishes to PyPI (Trusted Publishing/OIDC) and ghcr
  (multi-arch).

## Hard-won rules

- **Never `git add -A` without excluding runtime state.** A local server
  creates `toolgate.db*` in the repo root and `toolgate up` writes
  `.toolgate.env` (generated master + admin keys) next to it; a `.db-wal`
  file once leaked private keys into a public commit and a `.toolgate.env`
  was tracked for two weeks. Both are gitignored now; still stage explicit
  paths, or exclude with `':!*.db' ':!*.db-wal' ':!*.db-shm' ':!.toolgate.env'`.
- **Run ruff unpiped before every commit** — piped exit codes have let lint
  failures reach CI twice.
- gitleaks scans history: never quote secret-looking prose in comments
  (including inside `.gitleaksignore` itself); custom `tgk_`/`opk_` rules live
  in `.gitleaks.toml`.
- Tests fake all externals (httpx MockTransport, injected mailer/KMS/S3/Rekor,
  fake OAuth provider); CI needs no network, keys, or secrets. Keep it that way.
- The SQLite store's SQL is intentionally portable; `PostgresStore` inherits it
  and overrides only JSON-path operators (`json_extract` → `jsonb`),
  unique-violation handling, schema DDL, and disables the doc cache. If you add
  store SQL with `json_extract`, add the PG override.
- `TOOLGATE_PUBLIC_URL` must exactly match what clients use — PoP proofs bind
  to it (most common integration failure).
