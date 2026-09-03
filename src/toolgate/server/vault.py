import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class SealedSecret:
    iv: str
    ct: str  # ciphertext with the GCM tag appended (AESGCM convention)


class Vault:
    """AES-256-GCM secret sealing. The master key never leaves the server
    process; sealed blobs are what the store persists. KMS envelope encryption
    is the production upgrade path (issue #8)."""

    def __init__(self, master_key: str) -> None:
        self._aead = AESGCM(hashlib.sha256(master_key.encode()).digest())

    def seal(self, plaintext: str) -> SealedSecret:
        iv = os.urandom(12)
        ct = self._aead.encrypt(iv, plaintext.encode(), None)
        return SealedSecret(
            iv=base64.b64encode(iv).decode(),
            ct=base64.b64encode(ct).decode(),
        )

    def open(self, sealed: SealedSecret) -> str:
        pt = self._aead.decrypt(
            base64.b64decode(sealed.iv), base64.b64decode(sealed.ct), None
        )
        return pt.decode()
