# Deployment Guide

> Toolgate 0.3 · Last updated 2026-09-03

## Runtime requirements

- Python ≥ 3.12 (3.13 in CI)
- One writable volume for the SQLite database (or `:memory:` for ephemeral demos)
- Outbound HTTPS to your upstreams

## Configuration

All configuration is environment-based. There are no config files.

| Variable | Required in prod | Default | Purpose |
| --- | --- | --- | --- |
| `TOOLGATE_MASTER_KEY` | **yes** | dev fallback stored in DB + warning | Vault sealing key (AES-256-GCM). Losing it orphans all sealed upstream secrets. |
| `TOOLGATE_ADMIN_KEY` | **yes** | generated + persisted; only its fingerprint is logged at boot (never the key itself) | Control-plane authentication |
| `TOOLGATE_PUBLIC_URL` | **yes** | `http://localhost:8484` | External base URL. **Must match exactly what clients use** — PoP proofs bind to it (`htu`). Behind a proxy, set it to the public origin. |
| `TOOLGATE_ISSUER` | no | = public URL | Token `iss` |
| `TOOLGATE_DB` | no | `toolgate.db` | SQLite path |
| `PORT` | no | `8484` | Listen port |

Startup check: run with all four production variables set; the boot log must **not** contain the DEV MODE vault warning.

## Local / bare process

```bash
uv sync
TOOLGATE_MASTER_KEY=$(openssl rand -base64 32) \
TOOLGATE_ADMIN_KEY=$(openssl rand -hex 24) \
TOOLGATE_PUBLIC_URL=https://gate.internal.example \
uv run toolgate-server
```

## Container

```dockerfile
FROM python:3.13-slim
# Pin the uv base image to a specific release — never :latest — so builds are reproducible.
COPY --from=ghcr.io/astral-sh/uv:0.4.20 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY src ./src
RUN uv sync --frozen --no-dev
# Run as a non-root user, not root.
RUN useradd --system --uid 10001 toolgate && chown -R toolgate /app
USER toolgate
EXPOSE 8484
CMD ["uv", "run", "toolgate-server"]
```

Container hardening recommendations:

- **Do not run as root.** The example creates an unprivileged `toolgate` user and switches to it with `USER`; the process needs only read access to its code and write access to the `TOOLGATE_DB` volume.
- **Pin the base image.** Replace `ghcr.io/astral-sh/uv:0.4.20` and `python:3.13-slim` with digests or specific version tags you have reviewed — `:latest` makes builds non-reproducible and pulls in unreviewed changes.

## Cloud Run

```bash
gcloud run deploy toolgate \
  --source . \
  --region europe-west1 \
  --min-instances 1 --max-instances 1 \
  --no-allow-unauthenticated \
  --set-env-vars TOOLGATE_PUBLIC_URL=https://toolgate-<hash>-ew.a.run.app \
  --set-secrets TOOLGATE_MASTER_KEY=toolgate-master:latest,TOOLGATE_ADMIN_KEY=toolgate-admin:latest
```

Constraints to respect:

- **Deploy with authentication required.** The example passes `--no-allow-unauthenticated` so the service is not reachable by anonymous callers. The control plane (`/v1/control/*`, the admin plane) must never be exposed publicly without authentication — front it with IAM invoker permissions, an authenticating proxy, or an internal-only ingress rather than a public unauthenticated URL.
- **`max-instances 1` while on SQLite.** The store is single-writer; horizontal scaling requires the Postgres store (issue #16). Budget atomicity and jti single-use guarantees hold only within one instance.
- Mount a volume (Cloud Run volume mounts / GCS FUSE) for `TOOLGATE_DB`, or accept that instance recycling resets state.
- Keep secrets in Secret Manager, never in env-var literals in CI.

## Production checklist

- [ ] `TOOLGATE_MASTER_KEY` from KMS/Secret Manager; no DEV MODE warning at boot
- [ ] `TOOLGATE_PUBLIC_URL` equals the exact public origin (PoP breaks otherwise — this is the most common integration error)
- [ ] TLS termination in front of the service; HTTP disabled
- [ ] Admin key distribution restricted; rotate by setting a new `TOOLGATE_ADMIN_KEY`
- [ ] Audit export scheduled (`GET /v1/control/audit` → object storage) and retained ≥ 6 months (EU AI Act Art 26(6) readiness)
- [ ] `GET /v1/control/audit/verify` wired into monitoring — a `valid: false` is a page-immediately event
- [ ] Backup strategy for the SQLite file (litestream or scheduled snapshot)
