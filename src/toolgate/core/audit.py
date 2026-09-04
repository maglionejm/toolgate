import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json
from .types import AuditRecord, AuditRecordInput, Checkpoint

GATE_KEY_ROTATION_TOOL = "gate-key-rotation"

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
    sig_kid: str | None = None,
) -> AuditRecord:
    body = record_input.model_dump(mode="json", exclude_none=True)
    body["seq"] = prev.seq + 1 if prev else 1
    body["prevHash"] = prev.hash if prev else GENESIS_HASH
    if sig_kid is not None:
        body["sigKid"] = sig_kid
    record_hash = _compute_hash(body)
    sig = _sign_hash(record_hash, gate_private_jwk)
    return AuditRecord.model_validate({**body, "hash": record_hash, "sig": sig})


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    length: int
    broken_at_seq: int | None = None
    reason: str | None = None


def _coerce_verify_key(key: VerifyKey) -> Ed25519PublicKey | None:
    if isinstance(key, Ed25519PublicKey):
        return key
    try:
        return verify_key_from_jwk(key)
    except (KeyError, ValueError):
        return None


def _is_jwks_mapping(key: VerifyKey | dict[str, VerifyKey]) -> bool:
    return isinstance(key, dict) and "kty" not in key


def verify_audit_chain(
    records: list[AuditRecord],
    gate_public_jwk: VerifyKey | dict[str, VerifyKey],
) -> ChainVerification:
    """Verify hash linkage and per-record signatures.

    Single-key mode (a JWK dict or key object): every signature is checked
    against that one key — the pre-rotation behavior.

    JWKS mode (a mapping of kid -> key): signatures are checked against the
    record's `sigKid`, and key-rotation *lineage* is enforced — only the kid of
    the first record (or legacy unkeyed records, verified with the lineage
    root) is trusted a priori; any other kid must first be introduced by a
    `gate-key-rotation` handoff record signed under an already-trusted kid.
    """
    jwks_mode = _is_jwks_mapping(gate_public_jwk)
    if jwks_mode:
        keys = {kid: _coerce_verify_key(k) for kid, k in gate_public_jwk.items()}  # type: ignore[union-attr]
        root_kid = records[0].sigKid if records else None
        trusted_kids: set[str | None] = {root_kid, None}
        root_key = keys.get(root_kid) if root_kid is not None else None
    else:
        only = _coerce_verify_key(gate_public_jwk)  # type: ignore[arg-type]
        keys = {}
        trusted_kids = set()
        root_key = only

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

        if jwks_mode:
            if record.sigKid not in trusted_kids:
                return _broken(
                    len(records),
                    record.seq,
                    f"kid {record.sigKid} used before a handoff introduced it",
                )
            key = keys.get(record.sigKid) if record.sigKid is not None else root_key
            if key is None:
                return _broken(len(records), record.seq, f"unknown signing kid {record.sigKid}")
        else:
            key = root_key

        if key is None or not _verify_hash_signature(record.hash, record.sig, key):
            return _broken(len(records), record.seq, "signature invalid")

        if jwks_mode and record.action.tool == GATE_KEY_ROTATION_TOOL and record.meta:
            new_kid = record.meta.get("newKid")
            if isinstance(new_kid, str):
                trusted_kids.add(new_kid)
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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_detached_jws(payload: bytes, private_key: SigningKey, *, kid: str) -> str:
    """Detached compact JWS (RFC 7515 appendix F) over the exact payload bytes,
    signed with the gate key — the same signing discipline as the audit chain.
    Used for outbound webhook notifications: the receiver re-attaches the body
    it received and verifies against the gate's published JWKS."""
    header = _b64url_encode(
        json.dumps(
            {"alg": "EdDSA", "typ": "tg-hook+jws", "kid": kid}, separators=(",", ":")
        ).encode()
    )
    key = (
        private_key
        if isinstance(private_key, Ed25519PrivateKey)
        else signing_key_from_jwk(private_key)
    )
    sig = key.sign(f"{header}.{_b64url_encode(payload)}".encode())
    return f"{header}..{_b64url_encode(sig)}"


def verify_detached_jws(
    jws: str, payload: bytes, gate_public_jwk: VerifyKey | dict[str, VerifyKey]
) -> bool:
    """Verify a detached JWS against the payload bytes. Accepts a single key or
    a kid -> key JWKS mapping (the shape served at /v1/keys)."""
    parts = jws.split(".")
    if len(parts) != 3 or parts[1] != "":
        return False
    header_b64, _, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
    except (ValueError, TypeError):
        return False
    if not isinstance(header, dict) or header.get("alg") != "EdDSA":
        return False
    if _is_jwks_mapping(gate_public_jwk):
        candidate = gate_public_jwk.get(header.get("kid"))  # type: ignore[union-attr]
        key = _coerce_verify_key(candidate) if candidate is not None else None
    else:
        key = _coerce_verify_key(gate_public_jwk)  # type: ignore[arg-type]
    if key is None:
        return False
    try:
        key.verify(_b64url_decode(sig_b64), f"{header_b64}.{_b64url_encode(payload)}".encode())
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# Merkle checkpoints (RFC 6962-style domain separation). A checkpoint commits
# to the first `seq` record hashes; anchoring it externally means rewriting
# history is detectable even by a party that no longer trusts the gate key.
# ---------------------------------------------------------------------------


def merkle_root(record_hashes: list[str]) -> str:
    """RFC 6962 tree: leaf = SHA-256(0x00 || leaf_bytes), node = SHA-256(0x01 || l || r).
    Odd nodes are promoted unchanged. Input hashes are the records' hex hashes."""
    if not record_hashes:
        return GENESIS_HASH
    level = [hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest() for h in record_hashes]
    while len(level) > 1:
        paired = []
        for i in range(0, len(level) - 1, 2):
            paired.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            paired.append(level[-1])
        level = paired
    return level[0].hex()


def make_checkpoint(
    records: list[AuditRecord],
    gate_private_jwk: SigningKey,
    *,
    ts: str,
    sig_kid: str | None = None,
) -> Checkpoint:
    root = merkle_root([r.hash for r in records])
    body: dict[str, Any] = {"seq": len(records), "root": root, "ts": ts}
    if sig_kid is not None:
        body["sigKid"] = sig_kid
    sig = _sign_hash(sha256_hex(canonical_json(body)), gate_private_jwk)
    return Checkpoint.model_validate({**body, "sig": sig})


def verify_checkpoint(
    checkpoint: Checkpoint,
    records: list[AuditRecord],
    gate_public_jwk: VerifyKey | dict[str, VerifyKey],
) -> bool:
    """A checkpoint holds iff its root equals the recomputed root over the
    first `seq` records and its signature verifies under its kid."""
    if checkpoint.seq > len(records):
        return False
    if merkle_root([r.hash for r in records[: checkpoint.seq]]) != checkpoint.root:
        return False
    body = checkpoint.model_dump(mode="json", exclude_none=True)
    body.pop("sig")
    if _is_jwks_mapping(gate_public_jwk):
        candidate = gate_public_jwk.get(checkpoint.sigKid)  # type: ignore[union-attr]
        key = _coerce_verify_key(candidate) if candidate is not None else None
    else:
        key = _coerce_verify_key(gate_public_jwk)  # type: ignore[arg-type]
    if key is None:
        return False
    return _verify_hash_signature(sha256_hex(canonical_json(body)), checkpoint.sig, key)
