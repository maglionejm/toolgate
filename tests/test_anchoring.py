"""Transparency-log anchoring + WORM retention (#12, spec: add-audit-external-anchoring).

A faked Rekor-compatible log implements real RFC 6962 tree math and signs its
roots with a test key, so inclusion proofs and the pinned-trust-root check are
exercised for real — including the post-compromise rewrite scenario.
"""

import hashlib
import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from toolgate.core import (
    AuditAction,
    AuditActor,
    AuditDecision,
    AuditRecordInput,
    AuditResult,
    anchor_leaf_hash,
    append_audit_record,
    canonical_json,
    detect_anchor_divergence,
    new_id,
    verify_audit_chain,
    verify_checkpoint,
    verify_checkpoint_anchor,
)
from toolgate.server import create_app, create_app_context
from toolgate.worm import export_bundle_fs, export_bundle_s3

BASE = "http://testserver"
REKOR_URL = "https://rekor.example"


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode()


def _mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle tree head over leaf hashes."""
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def _path(m: int, leaves: list[bytes]) -> list[bytes]:
    """RFC 6962 audit path for leaf m."""
    if len(leaves) == 1:
        return []
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


class FakeRekor:
    """Rekor-compatible log: appends hashedrekord entries, returns real
    inclusion proofs, signs roots with its own Ed25519 log key."""

    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.log_id = "fake-rekor-log"
        self.leaves: list[bytes] = []
        self.fail = False

    @property
    def trust_root_pem(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            return httpx.Response(500, json={"error": "log unavailable"})
        entry = json.loads(request.content)
        digest = entry["spec"]["data"]["hash"]["value"]
        self.leaves.append(anchor_leaf_hash(digest))
        index = len(self.leaves) - 1
        root = _mth(self.leaves)
        signed_body = canonical_json(
            {"logId": self.log_id, "rootHash": root.hex(), "treeSize": len(self.leaves)}
        ).encode()
        return httpx.Response(
            201,
            json={
                hashlib.sha256(digest.encode()).hexdigest(): {
                    "logID": self.log_id,
                    "logIndex": index,
                    "verification": {
                        "inclusionProof": {
                            "logIndex": index,
                            "rootHash": root.hex(),
                            "treeSize": len(self.leaves),
                            "hashes": [h.hex() for h in _path(index, self.leaves)],
                            "signedRoot": _b64(self.key.sign(signed_body)),
                        }
                    },
                }
            },
        )


class Env:
    def __init__(self) -> None:
        self.rekor = FakeRekor()
        self.ctx = create_app_context(
            db_path=":memory:",
            public_url=BASE,
            rekor_url=REKOR_URL,
            rekor_http=httpx.Client(transport=httpx.MockTransport(self.rekor.handler)),
        )
        self.client = TestClient(create_app(self.ctx))
        self.admin = {"x-toolgate-admin-key": self.ctx.config.admin_key}

    def record(self, tool: str = "read") -> None:
        self.ctx.audit.record(
            AuditRecordInput(
                id=new_id("evt"),
                tenantId="tnt_test",
                ts="2026-09-14T00:00:00+00:00",
                actor=AuditActor(agentId="a", userId="u", grantId="g", tokenJti="j"),
                action=AuditAction(callId=new_id("call"), upstream="crm", tool=tool, argsHash="0"),
                decision=AuditDecision(effect="allow", source="rule", reason="test"),
                result=AuditResult(status="executed"),
            )
        )


@pytest.fixture()
def env() -> Env:
    return Env()


# --- anchoring ------------------------------------------------------------------------


def test_checkpoint_anchored_with_stored_proof(env: Env) -> None:
    for _ in range(3):
        env.record()
    env.ctx.audit.checkpoint()
    assert env.ctx.anchor_worker is not None
    assert env.ctx.anchor_worker.process_pending() == 1

    cp = env.ctx.store.list_checkpoints()[-1]
    assert cp.anchor is not None
    assert cp.anchor["logId"] == env.rekor.log_id
    assert cp.anchor["logIndex"] == 0
    assert cp.anchor["rootHash"] and cp.anchor["uuid"]

    # Additive evidence: the gate signature over the checkpoint still verifies.
    assert verify_checkpoint(cp, env.ctx.store.list_audit(), env.ctx.audit.verify_jwks())

    # Bundle export is v2 and carries the anchor.
    bundle = env.client.get("/v1/control/audit/bundle", headers=env.admin).json()
    assert bundle["version"] == 2
    assert bundle["checkpoints"][-1]["anchor"]["logIndex"] == 0

    # Verify endpoint reports the anchored ratio.
    verify = env.client.get("/v1/control/audit/verify", headers=env.admin).json()
    assert verify["checkpoints_anchored"] >= 1


def test_offline_anchor_verification_against_pinned_root(env: Env) -> None:
    env.record()
    env.ctx.audit.checkpoint()
    env.ctx.anchor_worker.process_pending()
    cp = env.ctx.store.list_checkpoints()[-1]

    assert verify_checkpoint_anchor(cp, env.rekor.trust_root_pem)

    # A different log key must not verify — the trust root is pinned.
    other = FakeRekor()
    assert not verify_checkpoint_anchor(cp, other.trust_root_pem)

    # Tampered evidence fails.
    tampered = cp.model_copy(deep=True)
    assert tampered.anchor is not None
    tampered.anchor["rootHash"] = "0" * 64
    assert not verify_checkpoint_anchor(tampered, env.rekor.trust_root_pem)

    # A checkpoint whose signed bytes changed no longer matches its anchor.
    moved = cp.model_copy(deep=True)
    moved.ts = "1999-01-01T00:00:00+00:00"
    assert not verify_checkpoint_anchor(moved, env.rekor.trust_root_pem)


def test_multi_checkpoint_inclusion_proofs(env: Env) -> None:
    """Odd tree sizes exercise the full RFC 6962 audit-path math."""
    for i in range(5):
        env.record(tool=f"t{i}")
        env.ctx.audit.checkpoint()
    env.ctx.anchor_worker.process_pending()
    checkpoints = env.ctx.store.list_checkpoints()
    assert len(checkpoints) == 5
    for cp in checkpoints:
        assert cp.anchor is not None
        assert verify_checkpoint_anchor(cp, env.rekor.trust_root_pem), cp.seq


def test_rekor_outage_degrades_healthz_and_recovers(env: Env) -> None:
    env.record()
    env.ctx.audit.checkpoint()
    env.rekor.fail = True
    for _ in range(3):
        env.ctx.anchor_worker.process_pending(force=True)
    assert env.ctx.anchor_worker.consecutive_failures == 3

    health = env.client.get("/healthz").json()
    assert health["anchoring"]["enabled"] is True
    assert health["anchoring"]["degraded"] is True
    assert health["anchoring"]["anchored"] == 0

    # Log comes back: anchoring resumes and the failure state clears.
    env.rekor.fail = False
    assert env.ctx.anchor_worker.process_pending(force=True) == 1
    health = env.client.get("/healthz").json()
    assert health["anchoring"]["degraded"] is False
    assert health["anchoring"]["anchored"] == 1


def test_post_compromise_rewrite_detected_by_anchor(env: Env) -> None:
    """An attacker with every current gate key re-signs a rewritten chain and
    fresh checkpoints — chain verification passes, the anchor exposes it."""
    for i in range(4):
        env.record(tool=f"t{i}")
    env.ctx.audit.checkpoint()
    env.ctx.anchor_worker.process_pending()
    anchored_cp = env.ctx.store.list_checkpoints()[-1]
    originals = env.ctx.store.list_audit()

    # Full-power rewrite: change one action, rebuild and re-sign every record.
    gate_jwk = env.ctx.gate_keys.private_jwk
    kid = env.ctx.gate_keys.kid
    rewritten = []
    prev = None
    for record in originals:
        body = AuditRecordInput.model_validate(record.model_dump(mode="json", exclude_none=True))
        if record.seq == 2:
            body.action.tool = "delete_everything"  # the lie being covered up
        prev = append_audit_record(prev, body, gate_jwk, sig_kid=kid)
        rewritten.append(prev)

    # Signatures alone cannot catch this: the attacker holds the key.
    assert verify_audit_chain(rewritten, env.ctx.audit.verify_jwks()).valid

    # The anchored checkpoint is intact evidence...
    assert verify_checkpoint_anchor(anchored_cp, env.rekor.trust_root_pem)
    # ...and the presented history no longer matches it: divergence report.
    divergences = detect_anchor_divergence(rewritten, [anchored_cp])
    assert divergences and divergences[0]["seq"] == anchored_cp.seq
    assert divergences[0]["anchoredRoot"] != divergences[0]["recomputedRoot"]

    # The untouched history still matches — no false positive.
    assert detect_anchor_divergence(originals, [anchored_cp]) == []


# --- WORM retention -------------------------------------------------------------------


def _bundle(env: Env) -> dict[str, Any]:
    return env.client.get("/v1/control/audit/bundle", headers=env.admin).json()


def test_worm_fs_export_write_once(env: Env, tmp_path: Any) -> None:
    env.record()
    env.ctx.audit.checkpoint()
    env.ctx.anchor_worker.process_pending()

    entry = export_bundle_fs(_bundle(env), tmp_path, retention_days=200)
    path = tmp_path / entry["file"]
    assert path.exists()
    assert (path.stat().st_mode & 0o777) == 0o444  # read-only on disk
    assert entry["anchored"] == 1

    # The manifest index records the export with its digest.
    manifest = (tmp_path / "manifest.jsonl").read_text().strip().splitlines()
    assert json.loads(manifest[-1])["sha256"] == entry["sha256"]

    # Write-once: the exported object refuses modification.
    with pytest.raises(PermissionError):
        path.write_text("tampered")

    # A second export appends to the index rather than replacing anything.
    env.record()
    env.ctx.audit.checkpoint()
    export_bundle_fs(_bundle(env), tmp_path, retention_days=200)
    manifest = (tmp_path / "manifest.jsonl").read_text().strip().splitlines()
    assert len(manifest) == 2


def test_worm_s3_export_uses_object_lock(env: Env) -> None:
    env.record()
    env.ctx.audit.checkpoint()
    calls: list[dict[str, Any]] = []

    class FakeS3:
        def put_object(self, **kwargs: Any) -> None:
            calls.append(kwargs)

    entry = export_bundle_s3(_bundle(env), "audit-bucket", s3_client=FakeS3())
    assert entry["bucket"] == "audit-bucket"
    assert len(calls) == 2  # bundle + manifest
    for call in calls:
        assert call["ObjectLockMode"] == "COMPLIANCE"
        assert call["ObjectLockRetainUntilDate"] > __import__("datetime").datetime.now(
            __import__("datetime").UTC
        )
    assert calls[0]["Key"].startswith("toolgate-audit/toolgate-audit-")
    assert calls[1]["Key"].startswith("toolgate-audit/manifests/")
