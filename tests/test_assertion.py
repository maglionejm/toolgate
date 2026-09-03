import pytest

from toolgate.core import (
    ErrorCodes,
    ToolgateError,
    generate_ed25519_key_pair,
    sign_client_assertion,
    sign_pop_proof,
    verify_client_assertion,
    verify_pop_proof,
)

CALL = dict(
    htm="POST",
    htu="https://gate.toolgate.test/v1/call/crm",
    access_token="token-abc",
)


def test_valid_client_assertion():
    agent = generate_ed25519_key_pair()
    assertion = sign_client_assertion(
        agent.private_jwk,
        agent_id="agt_1",
        token_url="https://control.toolgate.test/v1/token",
    )
    result = verify_client_assertion(
        agent.public_jwk,
        assertion,
        expected_audience="https://control.toolgate.test/v1/token",
    )
    assert result.agent_id == "agt_1"
    assert len(result.jti) > 8


def test_assertion_for_wrong_audience_rejected():
    agent = generate_ed25519_key_pair()
    assertion = sign_client_assertion(
        agent.private_jwk, agent_id="agt_1", token_url="https://evil.example/token"
    )
    with pytest.raises(ToolgateError) as err:
        verify_client_assertion(
            agent.public_jwk,
            assertion,
            expected_audience="https://control.toolgate.test/v1/token",
        )
    assert err.value.code == ErrorCodes.TOKEN_INVALID


def test_pop_proof_roundtrip():
    agent = generate_ed25519_key_pair()
    proof = sign_pop_proof(agent.private_jwk, **CALL)
    verified = verify_pop_proof(proof, expected_jkt=agent.kid, **CALL)
    assert verified.jkt == agent.kid


def test_pop_proof_from_different_key_rejected():
    agent = generate_ed25519_key_pair()
    thief = generate_ed25519_key_pair()
    proof = sign_pop_proof(thief.private_jwk, **CALL)
    with pytest.raises(ToolgateError) as err:
        verify_pop_proof(proof, expected_jkt=agent.kid, **CALL)
    assert err.value.code == ErrorCodes.PROOF_INVALID


def test_pop_proof_bound_to_other_token_rejected():
    agent = generate_ed25519_key_pair()
    proof = sign_pop_proof(
        agent.private_jwk, htm=CALL["htm"], htu=CALL["htu"], access_token="other-token"
    )
    with pytest.raises(ToolgateError) as err:
        verify_pop_proof(proof, expected_jkt=agent.kid, **CALL)
    assert err.value.code == ErrorCodes.PROOF_INVALID


def test_pop_proof_replayed_against_other_url_rejected():
    agent = generate_ed25519_key_pair()
    proof = sign_pop_proof(agent.private_jwk, **CALL)
    with pytest.raises(ToolgateError) as err:
        verify_pop_proof(
            proof,
            expected_jkt=agent.kid,
            htm=CALL["htm"],
            htu="https://gate.toolgate.test/v1/call/email",
            access_token=CALL["access_token"],
        )
    assert err.value.code == ErrorCodes.PROOF_INVALID
