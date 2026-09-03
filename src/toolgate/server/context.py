import json
import os
import secrets
from dataclasses import dataclass, field

import httpx
from jwcrypto import jwk

from toolgate.core import (
    AuditRecord,
    AuditRecordInput,
    ChainVerification,
    KeyPairJwk,
    append_audit_record,
    generate_ed25519_key_pair,
    signing_key_from_jwk,
    to_jwk,
    verify_audit_chain,
    verify_key_from_jwk,
)

from .ratelimit import SlidingWindowLimiter
from .store import Store
from .vault import Vault


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


class AuditLog:
    def __init__(self, store: Store, gate_keys: KeyPairJwk) -> None:
        self._store = store
        # Every gate decision signs a record: parse the Ed25519 keys once.
        self._signing_key = signing_key_from_jwk(gate_keys.private_jwk)
        self._verify_key = verify_key_from_jwk(gate_keys.public_jwk)
        self._last: AuditRecord | None = store.last_audit()

    def record(self, record_input: AuditRecordInput) -> AuditRecord:
        record = append_audit_record(self._last, record_input, self._signing_key)
        self._store.append_audit(record)
        self._last = record
        return record

    def verify(self) -> ChainVerification:
        return verify_audit_chain(self._store.list_audit(), self._verify_key)


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
    token_limiter: SlidingWindowLimiter
    gate_limiter: SlidingWindowLimiter
    http: httpx.AsyncClient = field(default_factory=httpx.AsyncClient)


def _load_or_create_keys(store: Store, name: str) -> KeyPairJwk:
    existing = store.get_setting(f"keys:{name}")
    if existing:
        data = json.loads(existing)
        return KeyPairJwk(
            kid=data["kid"], public_jwk=data["public_jwk"], private_jwk=data["private_jwk"]
        )
    keys = generate_ed25519_key_pair()
    store.set_setting(
        f"keys:{name}",
        json.dumps(
            {"kid": keys.kid, "public_jwk": keys.public_jwk, "private_jwk": keys.private_jwk}
        ),
    )
    return keys


def create_app_context(
    *,
    db_path: str | None = None,
    public_url: str | None = None,
    issuer: str | None = None,
    admin_key: str | None = None,
    master_key: str | None = None,
    dev_mode: bool = True,
    http_client: httpx.AsyncClient | None = None,
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
    store = Store(db_path or os.environ.get("TOOLGATE_DB", "toolgate.db"))

    master = master_key or os.environ.get("TOOLGATE_MASTER_KEY")
    if not master:
        if not dev_mode:
            raise RuntimeError(
                "TOOLGATE_MASTER_KEY is required. Refusing to fall back to a key stored "
                "alongside the sealed secrets. Set TOOLGATE_MASTER_KEY, or set TOOLGATE_DEV=1 "
                "for local development."
            )
        master = store.get_setting("dev_master_key") or secrets.token_urlsafe(32)
        store.set_setting("dev_master_key", master)
        print(
            "[toolgate] DEV MODE: vault master key stored alongside data. "
            "Set TOOLGATE_MASTER_KEY in production."
        )

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
    )

    gate_keys = _load_or_create_keys(store, "gate")
    control_keys = _load_or_create_keys(store, "control")
    return AppContext(
        store=store,
        vault=Vault(master),
        audit=AuditLog(store, gate_keys),
        config=config,
        control_keys=control_keys,
        gate_keys=gate_keys,
        control_signing_jwk=to_jwk(control_keys.private_jwk),
        control_verify_jwk=to_jwk(control_keys.public_jwk),
        token_limiter=SlidingWindowLimiter(config.token_rate_limit, config.rate_window_seconds),
        gate_limiter=SlidingWindowLimiter(config.gate_rate_limit, config.rate_window_seconds),
        http=http_client or httpx.AsyncClient(timeout=30.0),
    )
