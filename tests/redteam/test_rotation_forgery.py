"""Adversary: can write to the audit store and/or holds a NON-current key.
Guarantee: verification accepts only kids introduced by handoffs signed under
already-trusted kids; anchored checkpoints expose rewritten history."""

from datetime import UTC, datetime

from toolgate.core import (
    AuditAction,
    AuditActor,
    AuditDecision,
    AuditRecordInput,
    AuditResult,
    append_audit_record,
    generate_ed25519_key_pair,
    hash_args,
    signing_key_from_jwk,
    verify_audit_chain,
    verify_checkpoint,
)


def _record(n, tool="browse", meta=None):
    return AuditRecordInput(
        id=f"evt_{n}",
        tenantId="tnt",
        ts=datetime.now(UTC).isoformat(),
        actor=AuditActor(agentId="a", userId="u", grantId="g", tokenJti=str(n)),
        action=AuditAction(callId=f"c{n}", upstream="web", tool=tool, argsHash=hash_args({})),
        decision=AuditDecision(effect="allow", source="rule", reason="r"),
        result=AuditResult(status="executed"),
        meta=meta,
    )


def test_unintroduced_kid_rejected(target):
    """An attacker key signing records without a handoff must break the chain."""
    legit = target.ctx.gate_keyset[0]
    attacker = generate_ed25519_key_pair()
    r1 = append_audit_record(None, _record(1), signing_key_from_jwk(legit.private_jwk),
                             sig_kid=legit.kid)
    r2 = append_audit_record(r1, _record(2), signing_key_from_jwk(attacker.private_jwk),
                             sig_kid=attacker.kid)
    jwks = {legit.kid: legit.public_jwk, attacker.kid: attacker.public_jwk}
    v = verify_audit_chain([r1, r2], jwks)
    assert not v.valid and v.broken_at_seq == 2


def test_handoff_signed_by_untrusted_kid_grants_nothing(target):
    """A forged handoff signed by an attacker kid must not bootstrap trust."""
    legit = target.ctx.gate_keyset[0]
    attacker = generate_ed25519_key_pair()
    accomplice = generate_ed25519_key_pair()
    r1 = append_audit_record(None, _record(1), signing_key_from_jwk(legit.private_jwk),
                             sig_kid=legit.kid)
    forged_handoff = append_audit_record(
        r1, _record(2, tool="gate-key-rotation", meta={"newKid": accomplice.kid}),
        signing_key_from_jwk(attacker.private_jwk), sig_kid=attacker.kid,
    )
    r3 = append_audit_record(forged_handoff, _record(3),
                             signing_key_from_jwk(accomplice.private_jwk),
                             sig_kid=accomplice.kid)
    jwks = {k.kid: k.public_jwk for k in (legit,)} | {
        attacker.kid: attacker.public_jwk, accomplice.kid: accomplice.public_jwk
    }
    v = verify_audit_chain([r1, forged_handoff, r3], jwks)
    assert not v.valid and v.broken_at_seq == 2


def test_current_key_compromise_cannot_rewrite_anchored_past(target):
    """Adversary holds the CURRENT gate key. Future records are theirs — but an
    anchored checkpoint proves any rewrite of already-anchored history."""
    grant = target.grant()
    token = target.token(grant)
    assert target.signed_call(token, "web", "browse").status_code == 200
    cp_raw = target.post("/v1/control/audit/checkpoint", {})
    from toolgate.core import Checkpoint

    cp = Checkpoint.model_validate(cp_raw)
    records = target.ctx.store.list_audit()
    jwks = target.ctx.audit.verify_jwks()
    assert verify_checkpoint(cp, records, jwks)

    # Full-power rewrite: re-link and re-sign the whole chain with the real key.
    current = target.ctx.gate_keyset[0]
    signer = signing_key_from_jwk(current.private_jwk)
    rewritten, prev = [], None
    for i, _r in enumerate(records, start=1):
        body = _record(i, tool="innocent-cover-story")
        prev = append_audit_record(prev, body, signer, sig_kid=current.kid)
        rewritten.append(prev)
    # Internally consistent…
    assert verify_audit_chain(rewritten, jwks).valid
    # …but the anchored checkpoint exposes the rewrite.
    assert verify_checkpoint(cp, rewritten, jwks) is False
