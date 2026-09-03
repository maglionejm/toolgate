import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json
from .types import AuditRecord, AuditRecordInput

GENESIS_HASH = "0" * 64

SigningKey = dict[str, Any] | Ed25519PrivateKey
VerifyKey = dict[str, Any] | Ed25519PublicKey


def signing_key_from_jwk(private_jwk: dict[str, Any]) -> Ed25519PrivateKey:
    """Parse once and reuse: the gate signs every audit record with this key."""
    return Ed25519PrivateKey.from_private_bytes(_b64url_decode(private_jwk["d"]))


def verify_key_from_jwk(public_jwk: dict[str, Any]) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(public_jwk["x"]))


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def hash_args(args: dict[str, Any]) -> str:
    """Hash tool-call args for the audit trail without persisting payloads."""
    return sha256_hex(canonical_json(args))


def _compute_hash(record_body: dict[str, Any]) -> str:
    # Hash covers seq + prevHash + the whole record body: order and content sealed.
    return sha256_hex(canonical_json(record_body))


def append_audit_record(
    prev: AuditRecord | None,
    record_input: AuditRecordInput,
    gate_private_jwk: SigningKey,
) -> AuditRecord:
    body = record_input.model_dump(mode="json", exclude_none=True)
    body["seq"] = prev.seq + 1 if prev else 1
    body["prevHash"] = prev.hash if prev else GENESIS_HASH
    record_hash = _compute_hash(body)
    sig = _sign_hash(record_hash, gate_private_jwk)
    return AuditRecord.model_validate({**body, "hash": record_hash, "sig": sig})


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    length: int
    broken_at_seq: int | None = None
    reason: str | None = None


def verify_audit_chain(
    records: list[AuditRecord], gate_public_jwk: VerifyKey
) -> ChainVerification:
    key: Ed25519PublicKey | None
    if isinstance(gate_public_jwk, Ed25519PublicKey):
        key = gate_public_jwk
    else:
        try:
            key = verify_key_from_jwk(gate_public_jwk)
        except (KeyError, ValueError):
            key = None

    prev_hash = GENESIS_HASH
    prev_seq = 0
    for record in records:
        body = record.model_dump(mode="json", exclude_none=True)
        body.pop("hash")
        body.pop("sig")
        if record.seq != prev_seq + 1:
            return _broken(len(records), record.seq, f"sequence gap: expected {prev_seq + 1}")
        if record.prevHash != prev_hash:
            return _broken(len(records), record.seq, "prevHash does not match previous record")
        if _compute_hash(body) != record.hash:
            return _broken(len(records), record.seq, "record content does not match its hash")
        if key is None or not _verify_hash_signature(record.hash, record.sig, key):
            return _broken(len(records), record.seq, "signature invalid")
        prev_hash = record.hash
        prev_seq = record.seq
    return ChainVerification(valid=True, length=len(records))


def _broken(length: int, seq: int, reason: str) -> ChainVerification:
    return ChainVerification(valid=False, length=length, broken_at_seq=seq, reason=reason)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign_hash(hash_hex: str, private_key: SigningKey) -> str:
    key = (
        private_key
        if isinstance(private_key, Ed25519PrivateKey)
        else signing_key_from_jwk(private_key)
    )
    sig = key.sign(bytes.fromhex(hash_hex))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def _verify_hash_signature(hash_hex: str, sig: str, key: Ed25519PublicKey) -> bool:
    try:
        key.verify(_b64url_decode(sig), bytes.fromhex(hash_hex))
        return True
    except (InvalidSignature, ValueError):
        return False
