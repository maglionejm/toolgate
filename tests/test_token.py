import base64
import json

import pytest

from toolgate.core import (
    AuthorizationDetail,
    ErrorCodes,
    ToolgateError,
    generate_ed25519_key_pair,
    mint_capability_token,
    verify_capability_token,
)

AUTHZ = [AuthorizationDetail(upstream="crm", tools=["read_contact", "list_contacts"])]

BASE = dict(
    issuer="https://control.toolgate.test",
    audience="toolgate:gate",
    tenant_id="tnt_1",
    user_id="usr_1",
    agent_id="agt_1",
    grant_id="grt_1",
    scopes=["crm:read"],
    authorization_details=AUTHZ,
    agent_jkt="thumb-1",
)


def test_mint_and_verify_delegation_semantics():
    cp = generate_ed25519_key_pair()
    minted = mint_capability_token(cp.private_jwk, **BASE)
    claims = verify_capability_token(
        cp.public_jwk, minted.token, issuer=BASE["issuer"], audience=BASE["audience"]
    )
    assert claims.sub == "usr_1"
    assert claims.act.sub == "agt_1"
    assert claims.grant_id == "grt_1"
    assert claims.tenant == "tnt_1"
    assert claims.scope == "crm:read"
    assert claims.cnf.jkt == "thumb-1"
    assert claims.jti == minted.jti
    assert claims.txn == minted.txn
    assert claims.authorization_details == AUTHZ


def test_rejects_expired_token():
    cp = generate_ed25519_key_pair()
    minted = mint_capability_token(cp.private_jwk, **BASE, ttl_seconds=-10)
    with pytest.raises(ToolgateError) as err:
        verify_capability_token(
            cp.public_jwk, minted.token, issuer=BASE["issuer"], audience=BASE["audience"]
        )
    assert err.value.code == ErrorCodes.TOKEN_EXPIRED


def test_rejects_audience_mismatch():
    cp = generate_ed25519_key_pair()
    minted = mint_capability_token(cp.private_jwk, **BASE)
    with pytest.raises(ToolgateError) as err:
        verify_capability_token(
            cp.public_jwk, minted.token, issuer=BASE["issuer"], audience="other"
        )
    assert err.value.code == ErrorCodes.TOKEN_INVALID


def test_rejects_foreign_signature():
    cp = generate_ed25519_key_pair()
    impostor = generate_ed25519_key_pair()
    minted = mint_capability_token(impostor.private_jwk, **BASE)
    with pytest.raises(ToolgateError) as err:
        verify_capability_token(
            cp.public_jwk, minted.token, issuer=BASE["issuer"], audience=BASE["audience"]
        )
    assert err.value.code == ErrorCodes.TOKEN_INVALID


def test_rejects_tampered_payload():
    cp = generate_ed25519_key_pair()
    minted = mint_capability_token(cp.private_jwk, **BASE)
    header, payload, sig = minted.token.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    decoded["scope"] = "crm:read crm:write email:send"
    forged_payload = (
        base64.urlsafe_b64encode(json.dumps(decoded).encode()).rstrip(b"=").decode()
    )
    forged = f"{header}.{forged_payload}.{sig}"
    with pytest.raises(ToolgateError) as err:
        verify_capability_token(
            cp.public_jwk, forged, issuer=BASE["issuer"], audience=BASE["audience"]
        )
    assert err.value.code == ErrorCodes.TOKEN_INVALID
