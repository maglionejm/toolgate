import asyncio
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from jwcrypto import jwk

from toolgate.core import (
    GATE_KEY_ROTATION_TOOL,
    AuditAction,
    AuditActor,
    AuditDecision,
    AuditRecord,
    AuditRecordInput,
    AuditResult,
    ChainVerification,
    Checkpoint,
    KeyPairJwk,
    append_audit_record,
    generate_ed25519_key_pair,
    hash_args,
    make_checkpoint,
    new_id,
    signing_key_from_jwk,
    to_jwk,
    verify_audit_chain,
    verify_checkpoint,
)

from .anchor import AnchorWorker, RekorSink
from .notifier import Notifier
from .ratelimit import DbRateLimiter, SlidingWindowLimiter
from .store import Store
from .store_pg import PostgresStore, open_store
from .vault import AwsKmsProvider, EnvKekProvider, GcpKmsProvider, KekProvider, Vault


@dataclass(frozen=True)
class ServerConfig:
    issuer: str
    gate_audience: str
    # External base URL used as the htu binding for PoP proofs.
    public_url: str
    admin_key: str
    token_ttl_seconds: int = 120
    max_token_ttl_seconds: int = 300
    approval_ttl_seconds: int = 600
    # Per-grant request-rate ceilings (events per window). Complements the cost
    # budget, which only bounds total spend, not request frequency.
    rate_window_seconds: float = 60.0
    token_rate_limit: int = 60
    gate_rate_limit: int = 300
    # When False (production), upstream baseUrls must be https (or loopback http).
    # Dev/tests set this True so local http mock upstreams keep working.
    allow_insecure_upstreams: bool = False
    # Proof v2: gate calls carrying a body must bind it (cd claim).
    require_body_proofs: bool = True
    # A signed Merkle checkpoint is cut automatically every N audit records.
    checkpoint_interval: int = 64
    # Optional external witness: each checkpoint is POSTed here (fire-and-forget).
    anchor_url: str | None = None
    # Rekor-compatible transparency log; checkpoints are anchored with stored
    # inclusion proofs (TOOLGATE_REKOR_URL). See docs/OPERATIONS.md R7.
    rekor_url: str | None = None
    # MCP surface (/v1/mcp): bearer-token auth without PoP proofs (ADR 0009).
    mcp_enabled: bool = True
    # Taint scope: "txn" (per task token) or "grant" (whole delegation). Grant
    # scope closes the txn-splitting evasion — a fresh token cannot launder
    # taint — at the cost of one untrusted read tainting the entire grant.
    taint_scope: str = "txn"
    # Peers allowed to set X-Forwarded-For (comma-separated in
    # TOOLGATE_TRUSTED_PROXIES). Spoofed XFF from anyone else is ignored.
    trusted_proxies: tuple[str, ...] = ()


class AuditLog:
    """Signs every record with the *current* gate key and tracks kid lineage.

    Rotation appends a handoff record signed by the OLD key whose meta names
    the new kid — verifiers extend trust along that chain, never on the
    server's say-so. Checkpoints are cut every `checkpoint_interval` records
    and optionally POSTed to an external anchor."""

    def __init__(
        self,
        store: Store,
        gate_keyset: list[KeyPairJwk],
        *,
        checkpoint_interval: int = 64,
        anchor_url: str | None = None,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self._store = store
        self._keyset = gate_keyset  # newest first
        self._signing_key = signing_key_from_jwk(gate_keyset[0].private_jwk)
        self._sig_kid: str = gate_keyset[0].kid
        self._last: AuditRecord | None = store.last_audit()
        self._checkpoint_interval = checkpoint_interval
        self._anchor_url = anchor_url
        self._http = http

    @property
    def current_kid(self) -> str:
        return self._sig_kid

    def verify_jwks(self) -> dict[str, dict]:
        return {k.kid: k.public_jwk for k in self._keyset}

    def record(self, record_input: AuditRecordInput) -> AuditRecord:
        # Chain appends are serialized by the seq primary key: when another
        # instance wins the slot, rebase on the stored tail and re-sign (#16).
        for _ in range(25):
            record = append_audit_record(
                self._last, record_input, self._signing_key, sig_kid=self._sig_kid
            )
            if self._store.append_audit(record):
                self._last = record
                if record.seq % self._checkpoint_interval == 0:
                    self.checkpoint()
                return record
            self._last = self._store.last_audit()
        raise RuntimeError("audit chain append contention: could not win a seq slot")

    def checkpoint(self) -> Checkpoint:
        records = self._store.list_audit()
        cp = make_checkpoint(
            records,
            self._signing_key,
            ts=datetime.now(UTC).isoformat(),
            sig_kid=self._sig_kid,
        )
        self._store.put_checkpoint(cp)
        self._anchor(cp)
        return cp

    def _anchor(self, cp: Checkpoint) -> None:
        if not (self._anchor_url and self._http):
            return
        payload = cp.model_dump(mode="json", exclude_none=True)

        async def post() -> None:
            try:
                await self._http.post(self._anchor_url, json=payload)  # type: ignore[arg-type]
            except httpx.HTTPError as err:
                print(f"[toolgate] anchor POST failed (checkpoint seq {cp.seq}): {err}")

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no loop (tests/CLI paths): anchoring is best-effort
        loop.create_task(post())

    def rotate(self, new_keys: KeyPairJwk, *, rotated_by: str) -> AuditRecord:
        """Handoff signed by the OLD key naming the new kid, then switch."""
        handoff = AuditRecordInput(
            id=new_id("evt"),
            tenantId="-",
            ts=datetime.now(UTC).isoformat(),
            actor=AuditActor(agentId="control-plane", userId=rotated_by, grantId="-", tokenJti="-"),
            action=AuditAction(
                callId=new_id("call"),
                upstream="control",
                tool=GATE_KEY_ROTATION_TOOL,
                argsHash=hash_args(new_keys.public_jwk),
            ),
            decision=AuditDecision(
                effect="allow", source="approval", reason=f"gate key rotated to {new_keys.kid}"
            ),
            result=AuditResult(status="executed"),
            meta={"newKid": new_keys.kid},
        )
        record = self.record(handoff)
        self._keyset.insert(0, new_keys)
        self._signing_key = signing_key_from_jwk(new_keys.private_jwk)
        self._sig_kid = new_keys.kid
        self.checkpoint()
        return record

    def verify(self) -> ChainVerification:
        return verify_audit_chain(self._store.list_audit(), self.verify_jwks())

    def verify_checkpoints(self) -> tuple[int, int]:
        """(valid, total) across stored checkpoints."""
        records = self._store.list_audit()
        cps = self._store.list_checkpoints()
        valid = sum(1 for cp in cps if verify_checkpoint(cp, records, self.verify_jwks()))
        return valid, len(cps)


@dataclass
class AppContext:
    store: Store
    vault: Vault
    audit: AuditLog
    config: ServerConfig
    control_keys: KeyPairJwk
    gate_keys: KeyPairJwk
    # Parsed once at boot; every token mint/verify on the hot path reuses them.
    control_signing_jwk: jwk.JWK
    control_verify_jwk: jwk.JWK
    # Rotation keysets (newest first). Verification accepts any listed kid.
    control_keyset: list[KeyPairJwk] = field(default_factory=list)
    gate_keyset: list[KeyPairJwk] = field(default_factory=list)
    control_verify_jwks: dict[str, dict] = field(default_factory=dict)
    token_limiter: SlidingWindowLimiter | DbRateLimiter = field(
        default_factory=lambda: SlidingWindowLimiter(60, 60.0)
    )
    gate_limiter: SlidingWindowLimiter | DbRateLimiter = field(
        default_factory=lambda: SlidingWindowLimiter(300, 60.0)
    )
    http: httpx.AsyncClient = field(default_factory=httpx.AsyncClient)
    # In-memory failure telemetry by reason class (exposed via /healthz detail;
    # summarized into the audit chain at most hourly).
    auth_failure_counts: dict[str, int] = field(default_factory=dict)
    last_failure_summary: float = 0.0
    # Approval push notifications (webhook/Slack/email). Set right after
    # construction; None only in exotic embedding scenarios.
    notifier: Notifier | None = None
    # Transparency-log anchoring; None unless a Rekor URL is configured.
    anchor_worker: AnchorWorker | None = None

    def rotate_control_key(self) -> KeyPairJwk:
        new_keys = generate_ed25519_key_pair()
        self.control_keyset.insert(0, new_keys)
        _persist_keyset(self.store, "control", self.control_keyset)
        self.control_keys = new_keys
        self.control_signing_jwk = to_jwk(new_keys.private_jwk)
        self.control_verify_jwk = to_jwk(new_keys.public_jwk)
        self.control_verify_jwks[new_keys.kid] = new_keys.public_jwk
        return new_keys

    def rotate_gate_key(self, *, rotated_by: str) -> KeyPairJwk:
        new_keys = generate_ed25519_key_pair()
        self.audit.rotate(new_keys, rotated_by=rotated_by)
        self.gate_keyset.insert(0, new_keys)
        _persist_keyset(self.store, "gate", self.gate_keyset)
        self.gate_keys = new_keys
        return new_keys


def _persist_keyset(store: Store, name: str, keyset: list[KeyPairJwk]) -> None:
    store.set_setting(
        f"keyset:{name}",
        json.dumps(
            [
                {"kid": k.kid, "public_jwk": k.public_jwk, "private_jwk": k.private_jwk}
                for k in keyset
            ]
        ),
    )


def _load_or_create_keyset(store: Store, name: str) -> list[KeyPairJwk]:
    """Newest-first keyset; migrates the legacy single-key `keys:<name>` setting."""
    existing = store.get_setting(f"keyset:{name}")
    if existing:
        return [
            KeyPairJwk(kid=d["kid"], public_jwk=d["public_jwk"], private_jwk=d["private_jwk"])
            for d in json.loads(existing)
        ]
    legacy = store.get_setting(f"keys:{name}")
    if legacy:
        d = json.loads(legacy)
        keyset = [
            KeyPairJwk(kid=d["kid"], public_jwk=d["public_jwk"], private_jwk=d["private_jwk"])
        ]
    else:
        keyset = [generate_ed25519_key_pair()]
    _persist_keyset(store, name, keyset)
    return keyset


def create_app_context(
    *,
    db_path: str | None = None,
    public_url: str | None = None,
    issuer: str | None = None,
    admin_key: str | None = None,
    master_key: str | None = None,
    dev_mode: bool = True,
    anchor_url: str | None = None,
    rekor_url: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    notify_http: httpx.Client | None = None,
    rekor_http: httpx.Client | None = None,
    mailer: object | None = None,
    vault_provider: KekProvider | None = None,
) -> AppContext:
    """Build the application context.

    Secret handling is fail-closed unless ``dev_mode`` is set: with no vault
    master key and no admin key supplied (argument or environment), the only
    fallback is one stored *in the database beside the sealed secrets* — which
    makes encryption-at-rest decorative and hands an admin credential to anyone
    with the file. ``dev_mode`` (the library default, for tests and local
    embedding) keeps that convenience; the server entrypoint passes
    ``dev_mode=False`` unless ``TOOLGATE_DEV`` is set, so a production boot with
    missing keys refuses to start rather than silently self-provisioning.
    """
    # A postgres:// DSN activates the multi-instance store; a file path (or
    # :memory:) keeps single-node SQLite (#16).
    db_target = db_path or os.environ.get("TOOLGATE_DB", "toolgate.db")
    store = open_store(db_target)

    master = master_key or os.environ.get("TOOLGATE_MASTER_KEY")
    provider_name = os.environ.get("TOOLGATE_VAULT_PROVIDER", "env")
    provider: KekProvider | None = vault_provider

    if provider is None and provider_name in ("gcp-kms", "aws-kms"):
        # KMS custody: the KEK never leaves the cloud KMS; the master key is
        # only needed (optionally) to open legacy v1 blobs pending migration.
        kms_key = os.environ.get("TOOLGATE_KMS_KEY")
        if not kms_key:
            raise RuntimeError(
                f"TOOLGATE_KMS_KEY is required for vault provider {provider_name!r} "
                "(the KMS key resource name / ARN wrapping the data keys)."
            )
        provider = (
            GcpKmsProvider(kms_key) if provider_name == "gcp-kms" else AwsKmsProvider(kms_key)
        )
    elif provider is None and provider_name != "env":
        raise RuntimeError(
            f"unknown vault provider {provider_name!r}: use env, gcp-kms, or aws-kms"
        )

    if provider is None:
        # env provider: secrets are only as safe as the process environment.
        # Production must opt into that custody model explicitly (#8).
        allow_env = (os.environ.get("TOOLGATE_VAULT_ALLOW_ENV") or "").strip().lower() in (
            "1", "true", "yes", "on",
        )
        if not dev_mode and not allow_env:
            raise RuntimeError(
                "refusing the env vault provider in production: whoever reads the "
                "environment holds every upstream credential. Configure "
                "TOOLGATE_VAULT_PROVIDER=gcp-kms|aws-kms (+TOOLGATE_KMS_KEY), or "
                "explicitly accept env custody with TOOLGATE_VAULT_ALLOW_ENV=1."
            )
        if not master:
            if not dev_mode:
                raise RuntimeError(
                    "TOOLGATE_MASTER_KEY is required. Refusing to fall back to a key stored "
                    "alongside the sealed secrets. Set TOOLGATE_MASTER_KEY, or set "
                    "TOOLGATE_DEV=1 for local development."
                )
            master = store.get_setting("dev_master_key") or secrets.token_urlsafe(32)
            store.set_setting("dev_master_key", master)
            print(
                "[toolgate] DEV MODE: vault master key stored alongside data. "
                "Set TOOLGATE_MASTER_KEY in production."
            )
        previous = tuple(
            k.strip()
            for k in os.environ.get("TOOLGATE_MASTER_KEY_PREVIOUS", "").split(",")
            if k.strip()
        )
        provider = EnvKekProvider(master, previous)

    vault = Vault(master, provider=provider)
    try:
        # Fail closed: an unreachable or misconfigured KMS aborts the boot —
        # no silent fallback provider is ever substituted.
        vault.self_test()
    except Exception as err:
        raise RuntimeError(f"vault provider self-test failed (fail-closed): {err}") from err

    admin = admin_key or os.environ.get("TOOLGATE_ADMIN_KEY")
    if not admin:
        if not dev_mode:
            raise RuntimeError(
                "TOOLGATE_ADMIN_KEY is required. Refusing to fall back to a persisted admin "
                "credential. Set TOOLGATE_ADMIN_KEY, or set TOOLGATE_DEV=1 for local development."
            )
        admin = store.get_setting("admin_key") or f"tgk_{secrets.token_urlsafe(24)}"
        store.set_setting("admin_key", admin)

    url = public_url or os.environ.get("TOOLGATE_PUBLIC_URL", "http://localhost:8484")
    config = ServerConfig(
        issuer=issuer or os.environ.get("TOOLGATE_ISSUER", url),
        gate_audience="toolgate:gate",
        public_url=url,
        admin_key=admin,
        allow_insecure_upstreams=dev_mode,
        anchor_url=anchor_url or os.environ.get("TOOLGATE_ANCHOR_URL"),
        rekor_url=rekor_url or os.environ.get("TOOLGATE_REKOR_URL"),
        taint_scope=os.environ.get("TOOLGATE_TAINT_SCOPE", "txn"),
        trusted_proxies=tuple(
            p.strip()
            for p in os.environ.get("TOOLGATE_TRUSTED_PROXIES", "").split(",")
            if p.strip()
        ),
    )

    http = http_client or httpx.AsyncClient(timeout=30.0)
    gate_keyset = _load_or_create_keyset(store, "gate")
    control_keyset = _load_or_create_keyset(store, "control")
    control_keys = control_keyset[0]
    ctx = AppContext(
        store=store,
        vault=vault,
        audit=AuditLog(
            store,
            gate_keyset,
            checkpoint_interval=config.checkpoint_interval,
            anchor_url=config.anchor_url,
            http=http,
        ),
        config=config,
        control_keys=control_keys,
        gate_keys=gate_keyset[0],
        control_signing_jwk=to_jwk(control_keys.private_jwk),
        control_verify_jwk=to_jwk(control_keys.public_jwk),
        control_keyset=control_keyset,
        gate_keyset=gate_keyset,
        control_verify_jwks={k.kid: k.public_jwk for k in control_keyset},
        # Postgres deployments share rate-limit state across every instance;
        # single-node SQLite keeps the in-process sliding window.
        token_limiter=(
            DbRateLimiter(store, config.token_rate_limit, config.rate_window_seconds)
            if isinstance(store, PostgresStore)
            else SlidingWindowLimiter(config.token_rate_limit, config.rate_window_seconds)
        ),
        gate_limiter=(
            DbRateLimiter(store, config.gate_rate_limit, config.rate_window_seconds)
            if isinstance(store, PostgresStore)
            else SlidingWindowLimiter(config.gate_rate_limit, config.rate_window_seconds)
        ),
        http=http,
    )
    ctx.notifier = Notifier(
        store=store,
        vault=ctx.vault,
        public_url=url,
        # Resolved per delivery so gate-key rotation is picked up immediately.
        signer=lambda: (ctx.gate_keys.private_jwk, ctx.gate_keys.kid),
        http=notify_http,
        mailer=mailer,  # type: ignore[arg-type]
    )
    if config.rekor_url:
        ctx.anchor_worker = AnchorWorker(store, RekorSink(config.rekor_url, http=rekor_http))
    return ctx
