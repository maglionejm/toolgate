import json
import os
import secrets
from dataclasses import dataclass, field

import httpx

from toolgate.core import (
    AuditRecord,
    AuditRecordInput,
    ChainVerification,
    KeyPairJwk,
    append_audit_record,
    generate_ed25519_key_pair,
    verify_audit_chain,
)

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


class AuditLog:
    def __init__(self, store: Store, gate_keys: KeyPairJwk) -> None:
        self._store = store
        self._keys = gate_keys
        self._last: AuditRecord | None = store.last_audit()

    def record(self, record_input: AuditRecordInput) -> AuditRecord:
        record = append_audit_record(self._last, record_input, self._keys.private_jwk)
        self._store.append_audit(record)
        self._last = record
        return record

    def verify(self) -> ChainVerification:
        return verify_audit_chain(self._store.list_audit(), self._keys.public_jwk)


@dataclass
class AppContext:
    store: Store
    vault: Vault
    audit: AuditLog
    config: ServerConfig
    control_keys: KeyPairJwk
    gate_keys: KeyPairJwk
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
    http_client: httpx.AsyncClient | None = None,
) -> AppContext:
    store = Store(db_path or os.environ.get("TOOLGATE_DB", "toolgate.db"))

    master = master_key or os.environ.get("TOOLGATE_MASTER_KEY")
    if not master:
        master = store.get_setting("dev_master_key") or secrets.token_urlsafe(32)
        store.set_setting("dev_master_key", master)
        print(
            "[toolgate] DEV MODE: vault master key stored alongside data. "
            "Set TOOLGATE_MASTER_KEY in production."
        )

    admin = admin_key or os.environ.get("TOOLGATE_ADMIN_KEY")
    if not admin:
        admin = store.get_setting("admin_key") or f"tgk_{secrets.token_urlsafe(24)}"
        store.set_setting("admin_key", admin)

    url = public_url or os.environ.get("TOOLGATE_PUBLIC_URL", "http://localhost:8484")
    config = ServerConfig(
        issuer=issuer or os.environ.get("TOOLGATE_ISSUER", url),
        gate_audience="toolgate:gate",
        public_url=url,
        admin_key=admin,
    )

    gate_keys = _load_or_create_keys(store, "gate")
    return AppContext(
        store=store,
        vault=Vault(master),
        audit=AuditLog(store, gate_keys),
        config=config,
        control_keys=_load_or_create_keys(store, "control"),
        gate_keys=gate_keys,
        http=http_client or httpx.AsyncClient(timeout=30.0),
    )
