"""Vault: envelope encryption for upstream secrets (#8).

v2 blobs are sealed with a unique per-secret data key (DEK); only the KMS-
wrapped DEK is stored alongside the ciphertext, so nothing in the database is
decryptable without the key-encryption key (KEK) held by the provider:

- `env`      — KEK derived from TOOLGATE_MASTER_KEY (dev / single-host default)
- `gcp-kms`  — KEK never leaves Google Cloud KMS (encrypt/decrypt API)
- `aws-kms`  — KEK never leaves AWS KMS

v1 blobs (payload sealed directly under the master key) still open when a
master key is available and are re-sealed as v2 by `toolgate vault migrate`.
Plaintext DEKs exist only transiently in memory during seal/open/rotation;
secret payloads are never decrypted during KEK rotation.
"""

import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class SealedSecret:
    iv: str
    ct: str  # ciphertext with the GCM tag appended (AESGCM convention)
    # v2 envelope fields; None on legacy v1 blobs.
    v: int = 1
    kekId: str | None = None
    wrappedDek: str | None = None


class KekProvider(Protocol):
    """Wraps/unwraps per-secret data keys under a provider-held KEK."""

    kek_id: str

    def wrap(self, dek: bytes) -> bytes: ...

    def unwrap(self, wrapped: bytes, kek_id: str) -> bytes: ...


class EnvKekProvider:
    """KEK derived from the master key. Same custody model as v1 (whoever holds
    the environment holds the secrets) but with per-secret DEKs, so the blob
    format and rotation mechanics match the KMS providers exactly.

    `previous_keys` keeps old master keys usable for unwrap during a rotation
    window (TOOLGATE_MASTER_KEY_PREVIOUS, comma-separated)."""

    def __init__(self, master_key: str, previous_keys: tuple[str, ...] = ()) -> None:
        self._keks = {self._kek_id(k): AESGCM(hashlib.sha256(k.encode()).digest())
                      for k in (master_key, *previous_keys)}
        self.kek_id = self._kek_id(master_key)

    @staticmethod
    def _kek_id(master_key: str) -> str:
        return "env:" + hashlib.sha256(master_key.encode()).hexdigest()[:12]

    def wrap(self, dek: bytes) -> bytes:
        iv = os.urandom(12)
        return iv + self._keks[self.kek_id].encrypt(iv, dek, None)

    def unwrap(self, wrapped: bytes, kek_id: str) -> bytes:
        aead = self._keks.get(kek_id)
        if aead is None:
            raise RuntimeError(f"no master key available for KEK {kek_id}")
        return aead.decrypt(wrapped[:12], wrapped[12:], None)


class GcpKmsProvider:
    """DEKs wrapped by a Google Cloud KMS crypto key; the KEK never leaves KMS.
    Decrypt resolves old key versions automatically, so KEK rotation windows
    need no extra state here."""

    def __init__(self, key_name: str) -> None:
        try:
            from google.cloud import kms
        except ImportError as err:
            raise RuntimeError(
                "google-cloud-kms is required for the gcp-kms vault provider: "
                "pip install 'toolgate-io[gcp]'"
            ) from err
        self._client = kms.KeyManagementServiceClient()
        self._key_name = key_name
        self.kek_id = f"gcp:{key_name}"

    def wrap(self, dek: bytes) -> bytes:
        return self._client.encrypt(request={"name": self._key_name, "plaintext": dek}).ciphertext

    def unwrap(self, wrapped: bytes, kek_id: str) -> bytes:
        return self._client.decrypt(
            request={"name": self._key_name, "ciphertext": wrapped}
        ).plaintext


class AwsKmsProvider:
    """DEKs wrapped by an AWS KMS key. Decrypt infers the key from the
    ciphertext blob, so old KEK material stays usable during rotation."""

    def __init__(self, key_id: str) -> None:
        try:
            import boto3
        except ImportError as err:
            raise RuntimeError(
                "boto3 is required for the aws-kms vault provider: "
                "pip install 'toolgate-io[aws]'"
            ) from err
        self._client = boto3.client("kms")
        self._key_id = key_id
        self.kek_id = f"aws:{key_id}"

    def wrap(self, dek: bytes) -> bytes:
        return self._client.encrypt(KeyId=self._key_id, Plaintext=dek)["CiphertextBlob"]

    def unwrap(self, wrapped: bytes, kek_id: str) -> bytes:
        return self._client.decrypt(CiphertextBlob=wrapped)["Plaintext"]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


class Vault:
    """Envelope-encrypting vault. Sealing always produces v2 blobs under the
    configured provider; opening handles both v2 and legacy v1 (master key)."""

    def __init__(
        self, master_key: str | None = None, *, provider: KekProvider | None = None
    ) -> None:
        if provider is None:
            if master_key is None:
                raise RuntimeError("vault needs a master key or a KEK provider")
            provider = EnvKekProvider(master_key)
        self._provider = provider
        # Legacy v1 blobs are sealed directly under the master key.
        self._legacy = (
            AESGCM(hashlib.sha256(master_key.encode()).digest()) if master_key else None
        )

    @property
    def kek_id(self) -> str:
        return self._provider.kek_id

    def self_test(self) -> None:
        """Fail-closed boot probe: one wrap/unwrap round trip through the
        provider. Raises if the KMS is unreachable or misconfigured."""
        probe = os.urandom(32)
        if self._provider.unwrap(self._provider.wrap(probe), self._provider.kek_id) != probe:
            raise RuntimeError("vault provider self-test round trip failed")

    def seal(self, plaintext: str) -> SealedSecret:
        dek = os.urandom(32)
        iv = os.urandom(12)
        ct = AESGCM(dek).encrypt(iv, plaintext.encode(), None)
        return SealedSecret(
            iv=_b64(iv),
            ct=_b64(ct),
            v=2,
            kekId=self._provider.kek_id,
            wrappedDek=_b64(self._provider.wrap(dek)),
        )

    def open(self, sealed: SealedSecret) -> str:
        if sealed.v >= 2 and sealed.wrappedDek and sealed.kekId:
            dek = self._provider.unwrap(_unb64(sealed.wrappedDek), sealed.kekId)
            return AESGCM(dek).decrypt(_unb64(sealed.iv), _unb64(sealed.ct), None).decode()
        if self._legacy is None:
            raise RuntimeError(
                "legacy v1 blob but no master key available — set TOOLGATE_MASTER_KEY "
                "and run `toolgate vault migrate`"
            )
        return self._legacy.decrypt(_unb64(sealed.iv), _unb64(sealed.ct), None).decode()

    def rewrap(self, sealed: SealedSecret) -> SealedSecret:
        """KEK rotation step: unwrap the DEK under its old KEK and wrap it under
        the current one. The secret payload is never decrypted."""
        if not (sealed.v >= 2 and sealed.wrappedDek and sealed.kekId):
            raise RuntimeError("v1 blob cannot be rewrapped — migrate it first")
        dek = self._provider.unwrap(_unb64(sealed.wrappedDek), sealed.kekId)
        return SealedSecret(
            iv=sealed.iv,
            ct=sealed.ct,
            v=2,
            kekId=self._provider.kek_id,
            wrappedDek=_b64(self._provider.wrap(dek)),
        )

    def reseal(self, sealed: SealedSecret) -> SealedSecret:
        """Migration step: open a legacy v1 blob and seal it as v2."""
        return self.seal(self.open(sealed))
