"""KMS envelope vault (#8, spec: add-kms-envelope-vault).

The KMS is faked at the provider interface: real envelope mechanics (unique
DEK per secret, wrap/unwrap, KEK rotation, v1->v2 migration) run for real."""

import hashlib
import os
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from toolgate.server import create_app, create_app_context
from toolgate.server.vault import EnvKekProvider, SealedSecret, Vault

BASE = "http://testserver"


class FakeKms:
    """In-memory KMS: wraps DEKs under keys it never releases; scriptable
    outage; counts operations so tests can prove payloads stay sealed."""

    def __init__(self, kek_id: str = "fake-kms:key-1") -> None:
        self._keys = {kek_id: AESGCM(hashlib.sha256(kek_id.encode()).digest())}
        self.kek_id = kek_id
        self.down = False
        self.wraps = 0
        self.unwraps = 0

    def rotate(self, new_kek_id: str) -> None:
        """Server-side KEK rotation: new wraps use the new key; old wrapped
        DEKs stay decryptable (as GCP/AWS decrypt APIs do)."""
        self._keys[new_kek_id] = AESGCM(hashlib.sha256(new_kek_id.encode()).digest())
        self.kek_id = new_kek_id

    def wrap(self, dek: bytes) -> bytes:
        if self.down:
            raise RuntimeError("kms unavailable")
        self.wraps += 1
        iv = os.urandom(12)
        return iv + self._keys[self.kek_id].encrypt(iv, dek, None)

    def unwrap(self, wrapped: bytes, kek_id: str) -> bytes:
        if self.down:
            raise RuntimeError("kms unavailable")
        self.unwraps += 1
        return self._keys[kek_id].decrypt(wrapped[:12], wrapped[12:], None)


def _legacy_v1_blob(master_key: str, plaintext: str) -> SealedSecret:
    aead = AESGCM(hashlib.sha256(master_key.encode()).digest())
    iv = os.urandom(12)
    import base64

    return SealedSecret(
        iv=base64.b64encode(iv).decode(),
        ct=base64.b64encode(aead.encrypt(iv, plaintext.encode(), None)).decode(),
    )


# --- envelope mechanics ---------------------------------------------------------------


def test_seal_under_kms_stores_only_wrapped_material() -> None:
    kms = FakeKms()
    vault = Vault(provider=kms)
    sealed = vault.seal("upstream-api-key")

    assert sealed.v == 2
    assert sealed.kekId == kms.kek_id
    assert sealed.wrappedDek
    assert vault.open(sealed) == "upstream-api-key"

    # Nothing in the blob is decryptable without the KMS: a vault with a
    # different provider (or only a master key) cannot open it.
    with pytest.raises((KeyError, RuntimeError)):
        Vault(provider=FakeKms("fake-kms:other")).open(sealed)
    with pytest.raises((KeyError, RuntimeError)):
        Vault("some-master-key", provider=EnvKekProvider("some-master-key")).open(sealed)

    # Unique DEK per secret: two seals of the same plaintext share nothing.
    other = vault.seal("upstream-api-key")
    assert other.wrappedDek != sealed.wrappedDek and other.ct != sealed.ct


def test_env_provider_parity_and_rotation_window() -> None:
    vault = Vault("master-1")
    sealed = vault.seal("s")
    assert sealed.v == 2 and sealed.kekId and sealed.kekId.startswith("env:")
    assert vault.open(sealed) == "s"

    # Rotation window: the new master opens old blobs via previous_keys.
    rotated = Vault("master-2", provider=EnvKekProvider("master-2", previous_keys=("master-1",)))
    assert rotated.open(sealed) == "s"
    rewrapped = rotated.rewrap(sealed)
    assert rewrapped.kekId == EnvKekProvider("master-2").kek_id
    assert Vault("master-2").open(rewrapped) == "s"  # no previous key needed anymore

    # Without the old key in the window, the old blob is unreadable.
    with pytest.raises(RuntimeError):
        Vault("master-2").open(sealed)


def test_v1_blob_opens_with_master_and_fails_closed_without() -> None:
    legacy = _legacy_v1_blob("old-master", "legacy-secret")
    assert Vault("old-master", provider=FakeKms()).open(legacy) == "legacy-secret"
    with pytest.raises(RuntimeError, match="vault migrate"):
        Vault(provider=FakeKms()).open(legacy)


# --- boot wiring ----------------------------------------------------------------------


def test_boot_fails_closed_when_kms_down() -> None:
    kms = FakeKms()
    kms.down = True
    with pytest.raises(RuntimeError, match="self-test failed"):
        create_app_context(db_path=":memory:", public_url=BASE, vault_provider=kms)


def test_production_refuses_env_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOOLGATE_VAULT_PROVIDER", raising=False)
    monkeypatch.delenv("TOOLGATE_VAULT_ALLOW_ENV", raising=False)
    with pytest.raises(RuntimeError, match="env vault provider in production"):
        create_app_context(
            db_path=":memory:",
            public_url=BASE,
            dev_mode=False,
            master_key="m" * 32,
            admin_key="tgk_test",
        )
    # Explicit override keeps the 0.4 custody model available.
    monkeypatch.setenv("TOOLGATE_VAULT_ALLOW_ENV", "1")
    ctx = create_app_context(
        db_path=":memory:",
        public_url=BASE,
        dev_mode=False,
        master_key="m" * 32,
        admin_key="tgk_test",
    )
    assert ctx.vault.kek_id.startswith("env:")


def test_kms_provider_requires_key_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOOLGATE_VAULT_PROVIDER", "gcp-kms")
    monkeypatch.delenv("TOOLGATE_KMS_KEY", raising=False)
    with pytest.raises(RuntimeError, match="TOOLGATE_KMS_KEY"):
        create_app_context(db_path=":memory:", public_url=BASE)


# --- lifecycle endpoints ---------------------------------------------------------------


class Env:
    def __init__(self) -> None:
        from fastapi.testclient import TestClient

        self.kms = FakeKms()
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=BASE,
            master_key="boot-master",
            vault_provider=self.kms,
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": 1}))
            ),
        )
        self.client = TestClient(create_app(self.ctx))
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}

    def post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        res = self.client.post(path, headers=self.admin, json=body or {})
        assert res.status_code < 300, res.text
        return res.json()


@pytest.fixture()
def env() -> Env:
    return Env()


def test_rotate_kek_rewraps_without_decrypting_payloads(env: Env) -> None:
    for i in range(3):
        env.ctx.store.put_secret(f"sec_{i}", env.ctx.vault.seal(f"secret-{i}"))

    env.kms.rotate("fake-kms:key-2")
    baseline_unwraps = env.kms.unwraps
    out = env.post("/v1/control/vault/rotate-kek")
    assert out == {"rotated": 3, "skippedV1": 0, "kekId": "fake-kms:key-2"}

    # Exactly one unwrap per secret — DEKs only; payload AESGCM never ran
    # (payload decryption would require the DEK *and* produce plaintext we
    # never touch: ct/iv must be byte-identical after rotation).
    assert env.kms.unwraps == baseline_unwraps + 3
    for i in range(3):
        sealed = env.ctx.store.get_secret(f"sec_{i}")
        assert sealed is not None and sealed.kekId == "fake-kms:key-2"
        assert env.ctx.vault.open(sealed) == f"secret-{i}"

    # The rotation landed in the audit chain.
    records = [r for r in env.ctx.store.list_audit() if r.action.tool == "vault.rotate-kek"]
    assert records and records[-1].decision.source == "operator"


def test_migrate_bulk_converts_v1_blobs(env: Env) -> None:
    env.ctx.store.put_secret("sec_legacy_a", _legacy_v1_blob("boot-master", "alpha"))
    env.ctx.store.put_secret("sec_legacy_b", _legacy_v1_blob("boot-master", "beta"))
    env.ctx.store.put_secret("sec_new", env.ctx.vault.seal("gamma"))

    status = env.client.get("/v1/control/vault/status", headers=env.admin).json()
    assert status["v1Blobs"] == 2 and status["v2Blobs"] == 1

    out = env.post("/v1/control/vault/migrate")
    assert out["migrated"] == 2 and out["failures"] == []

    status = env.client.get("/v1/control/vault/status", headers=env.admin).json()
    assert status["v1Blobs"] == 0 and status["v2Blobs"] == 3
    expectations = (("sec_legacy_a", "alpha"), ("sec_legacy_b", "beta"), ("sec_new", "gamma"))
    for ref, expected in expectations:
        sealed = env.ctx.store.get_secret(ref)
        assert sealed is not None and sealed.v == 2
        assert env.ctx.vault.open(sealed) == expected

    records = [r for r in env.ctx.store.list_audit() if r.action.tool == "vault.migrate"]
    assert records


def test_kms_outage_fails_closed_on_open(env: Env) -> None:
    env.ctx.store.put_secret("sec_x", env.ctx.vault.seal("x"))
    env.kms.down = True
    sealed = env.ctx.store.get_secret("sec_x")
    assert sealed is not None
    with pytest.raises(RuntimeError, match="kms unavailable"):
        env.ctx.vault.open(sealed)
