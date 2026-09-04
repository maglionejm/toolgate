# Deployment Guide

> Toolgate 0.4 · Last updated 2026-09-12

## Runtime requirements

- Python ≥ 3.12 (3.13 in CI)
- One writable volume for the SQLite database (or `:memory:` for ephemeral demos)
- Outbound HTTPS to your upstreams

## Configuration

All configuration is environment-based. There are no config files.

| Variable | Required in prod | Default | Purpose |
| --- | --- | --- | --- |
| `TOOLGATE_VAULT_PROVIDER` | recommended | `env` | Secret custody: `env`, `gcp-kms`, or `aws-kms`. Production **refuses** `env` unless `TOOLGATE_VAULT_ALLOW_ENV=1` (see below). |
| `TOOLGATE_KMS_KEY` | with a KMS provider | — | KEK reference: GCP crypto-key resource name, or AWS KMS key id/ARN. |
| `TOOLGATE_MASTER_KEY` | with `env` provider | dev fallback stored in DB + warning | Vault KEK source for the `env` provider; also opens legacy v1 blobs pending `toolgate vault migrate`. Losing it orphans v1 secrets. |
| `TOOLGATE_MASTER_KEY_PREVIOUS` | no | — | Comma-separated old master keys kept unwrap-able during an env-provider KEK rotation window. |
| `TOOLGATE_ADMIN_KEY` | **yes** | generated + persisted; only its fingerprint is logged at boot (never the key itself) | Control-plane authentication |
| `TOOLGATE_PUBLIC_URL` | **yes** | `http://localhost:8484` | External base URL. **Must match exactly what clients use** — PoP proofs bind to it (`htu`). Behind a proxy, set it to the public origin. |
| `TOOLGATE_ISSUER` | no | = public URL | Token `iss` |
| `TOOLGATE_DB` | no | `toolgate.db` | SQLite path |
| `PORT` | no | `8484` | Listen port |

Startup check: run with the production variables set; the boot log must **not** contain the DEV MODE vault warning. Boot is fail-closed: an unreachable or misconfigured KMS aborts with a self-test error rather than silently falling back.

### Vault custody (KMS envelope encryption)

Every secret is sealed under its own data key (DEK); only the KMS-wrapped DEK is stored. Nothing in the database decrypts without the KEK, and the KEK never leaves the KMS.

**GCP** (`pip install 'toolgate-io[gcp]'`):

```bash
gcloud kms keyrings create toolgate --location=global
gcloud kms keys create vault-kek --location=global --keyring=toolgate --purpose=encryption
# service account needs roles/cloudkms.cryptoKeyEncrypterDecrypter
TOOLGATE_VAULT_PROVIDER=gcp-kms \
TOOLGATE_KMS_KEY=projects/PROJECT/locations/global/keyRings/toolgate/cryptoKeys/vault-kek \
toolgate server
```

**AWS** (`pip install 'toolgate-io[aws]'`):

```bash
aws kms create-key --description "toolgate vault KEK"
# instance/task role needs kms:Encrypt + kms:Decrypt on the key
TOOLGATE_VAULT_PROVIDER=aws-kms TOOLGATE_KMS_KEY=arn:aws:kms:...:key/... toolgate server
```

Migrating an existing (v1, master-key) store: boot with the KMS provider **plus** the old `TOOLGATE_MASTER_KEY`, run `toolgate vault migrate`, verify `toolgate vault status` shows zero v1 blobs, then drop the master key from the environment.

The `env` provider remains the single-host/dev custody model; accepting it in production requires `TOOLGATE_VAULT_ALLOW_ENV=1` — an explicit statement that whoever reads the environment holds every upstream credential.

## Local / bare process

```bash
uv sync
TOOLGATE_MASTER_KEY=$(openssl rand -base64 32) \
TOOLGATE_ADMIN_KEY=$(openssl rand -hex 24) \
TOOLGATE_PUBLIC_URL=https://gate.internal.example \
uv run toolgate-server
```

## Container (official)

```bash
toolgate up                      # generates .toolgate.env (0600) and runs the container
# or explicitly:
docker run -p 8484:8484 --env-file .toolgate.env -v toolgate-data:/data \
  ghcr.io/maglionejm/toolgate:latest
docker compose up                # compose.yaml in the repo
```

Images are published to `ghcr.io/maglionejm/toolgate` on every release. The container binds `TOOLGATE_HOST=0.0.0.0` via env and stores SQLite in the `/data` volume. The operator console ships in the image at `/console`.

Additional environment: `TOOLGATE_HOST` (default 127.0.0.1), `TOOLGATE_DEV=1` (dev-only fail-open secrets), `TOOLGATE_ANCHOR_URL` (checkpoint witness webhook).

## Container (custom build)

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
