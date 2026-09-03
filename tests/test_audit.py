from datetime import UTC, datetime, timedelta

from toolgate.core import (
    AuditRecord,
    AuditRecordInput,
    append_audit_record,
    generate_ed25519_key_pair,
    hash_args,
    verify_audit_chain,
)


def make_input(n: int) -> AuditRecordInput:
    ts = datetime.fromtimestamp(1757000000, tz=UTC) + timedelta(seconds=n)
    return AuditRecordInput.model_validate(
        {
            "id": f"evt_{n}",
            "tenantId": "tnt_1",
            "ts": ts.isoformat(),
            "actor": {
                "agentId": "agt_1",
                "userId": "usr_1",
                "grantId": "grt_1",
                "tokenJti": f"jti-{n}",
            },
            "action": {
                "callId": f"call_{n}",
                "upstream": "crm",
                "tool": "read_contact",
                "argsHash": hash_args({"contactId": n}),
            },
            "decision": {"effect": "allow", "source": "rule", "ruleId": "r1", "reason": "allowed"},
            "result": {"status": "executed", "httpStatus": 200, "latencyMs": 12, "costUnits": 1},
        }
    )


def build_chain(n: int, key) -> list[AuditRecord]:
    records: list[AuditRecord] = []
    prev: AuditRecord | None = None
    for i in range(1, n + 1):
        prev = append_audit_record(prev, make_input(i), key.private_jwk)
        records.append(prev)
    return records


def test_append_and_verify_chain():
    gate = generate_ed25519_key_pair()
    records = build_chain(5, gate)
    result = verify_audit_chain(records, gate.public_jwk)
    assert result.valid and result.length == 5


def test_detects_content_tampering():
    gate = generate_ed25519_key_pair()
    records = build_chain(3, gate)
    tampered = [r.model_copy(deep=True) for r in records]
    tampered[1].decision.reason = "cover-up"
    result = verify_audit_chain(tampered, gate.public_jwk)
    assert not result.valid and result.broken_at_seq == 2


def test_detects_record_removal():
    gate = generate_ed25519_key_pair()
    records = build_chain(3, gate)
    with_gap = [records[0], records[2]]
    assert not verify_audit_chain(with_gap, gate.public_jwk).valid


def test_detects_foreign_signature():
    gate = generate_ed25519_key_pair()
    rogue = generate_ed25519_key_pair()
    record = append_audit_record(None, make_input(1), rogue.private_jwk)
    assert not verify_audit_chain([record], gate.public_jwk).valid


def test_empty_chain_is_valid():
    gate = generate_ed25519_key_pair()
    result = verify_audit_chain([], gate.public_jwk)
    assert result.valid and result.length == 0
