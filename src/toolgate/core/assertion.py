"""Client assertions (RFC 7523 style) and DPoP-style proof-of-possession.

The PoP layer is hand-implemented: as of 2026 no maintained Python JOSE
library ships DPoP (authlib #315 open since 2021). The proof format is
Toolgate's own (`tg-pop+jwt`), matching RFC 9449's model: one-time JWS signed
by the agent key, embedding the public JWK, bound to method + URL + token hash.
"""

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from jwcrypto import jwk, jws, jwt

from .errors import ErrorCodes, ToolgateError
from .keys import KeyLike, public_jwk_from_private, to_jwk, validate_public_ed25519_jwk

CLIENT_ASSERTION_TYP = "tg-client+jwt"
POP_PROOF_TYP = "tg-pop+jwt"
_PROOF_MAX_AGE_SECONDS = 60
_PROOF_CLOCK_SKEW_SECONDS = 5

# ---------------------------------------------------------------------------
# Client assertion: how an agent authenticates to the control plane token
# endpoint. No shared secrets.
# ---------------------------------------------------------------------------


def sign_client_assertion(
    agent_private_jwk: KeyLike,
    *,
    agent_id: str,
    token_url: str,
    ttl_seconds: int = 60,
) -> str:
    key = to_jwk(agent_private_jwk)
    now = int(time.time())
    token = jwt.JWT(
        header={"alg": "EdDSA", "typ": CLIENT_ASSERTION_TYP},
        claims={
            "iss": agent_id,
            "sub": agent_id,
            "aud": token_url,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_urlsafe(12),
        },
    )
    token.make_signed_token(key)
    return token.serialize()


@dataclass(frozen=True)
class VerifiedAssertion:
    agent_id: str
    jti: str


def verify_client_assertion(
    agent_public_jwk: KeyLike,
    assertion: str,
    *,
    expected_audience: str,
) -> VerifiedAssertion:
    key = to_jwk(agent_public_jwk)
    verifier = jwt.JWT(check_claims={"aud": expected_audience, "exp": None})
    verifier.leeway = _PROOF_CLOCK_SKEW_SECONDS
    try:
        verifier.deserialize(assertion, key)
        header = json.loads(verifier.header)
        if header.get("typ") != CLIENT_ASSERTION_TYP:
            raise ValueError("client assertion has wrong typ")
        # Pin the algorithm: never let a symmetric/other-alg signature through
        # even if a non-Ed25519 key were somehow registered.
        if header.get("alg") != "EdDSA":
            raise ValueError(f"client assertion alg must be EdDSA, got {header.get('alg')!r}")
        claims = json.loads(verifier.claims)
        # RFC 7523 wants a single string audience; jwcrypto's check_claims is
        # satisfied by an array that merely *contains* the expected value, which
        # weakens the "audience is exactly this token URL" binding.
        if not isinstance(claims.get("aud"), str):
            raise ValueError("client assertion aud must be a single string")
        if not claims.get("iss") or claims["iss"] != claims.get("sub"):
            raise ValueError("client assertion must have iss == sub")
        if not isinstance(claims.get("jti"), str):
            raise ValueError("client assertion must have a jti")
        return VerifiedAssertion(agent_id=claims["sub"], jti=claims["jti"])
    except ToolgateError:
        raise
    except Exception as err:
        raise ToolgateError(
            ErrorCodes.TOKEN_INVALID, f"client assertion rejected: {err}"
        ) from err


# ---------------------------------------------------------------------------
# Proof of possession: every gate call carries a one-time proof signed by the
# agent key named in the capability token's cnf.jkt. A stolen token is useless
# without the key.
# ---------------------------------------------------------------------------


def access_token_hash(token: str) -> str:
    digest = hashlib.sha256(token.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def content_digest(body: bytes | str) -> str:
    """Proof v2 `cd` claim: base64url(SHA-256(raw request body)). Binding the
    proof to the exact bytes sent closes body substitution — a captured proof
    cannot authorize a different payload."""
    data = body.encode() if isinstance(body, str) else body
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def sign_pop_proof(
    agent_private_jwk: KeyLike,
    *,
    htm: str,
    htu: str,
    access_token: str,
    body: bytes | str | None = None,
) -> str:
    key = to_jwk(agent_private_jwk)
    if isinstance(agent_private_jwk, dict):
        header_jwk = public_jwk_from_private(agent_private_jwk)
    else:
        exported: dict[str, Any] = json.loads(key.export_public())
        header_jwk = {k: exported[k] for k in ("kty", "crv", "x")}
    claims: dict[str, Any] = {
        "htm": htm.upper(),
        "htu": htu,
        "ath": access_token_hash(access_token),
        "iat": int(time.time()),
        "jti": secrets.token_urlsafe(12),
    }
    if body is not None:
        claims["cd"] = content_digest(body)
    token = jwt.JWT(
        header={
            "alg": "EdDSA",
            "typ": POP_PROOF_TYP,
            "jwk": header_jwk,
        },
        claims=claims,
    )
    token.make_signed_token(key)
    return token.serialize()


@dataclass(frozen=True)
class VerifiedPopProof:
    jti: str
    jkt: str


def verify_pop_proof(
    proof: str,
    *,
    expected_jkt: str,
    htm: str,
    htu: str,
    access_token: str,
    body: bytes | str | None = None,
    require_body_binding: bool = False,
) -> VerifiedPopProof:
    try:
        signature = jws.JWS()
        signature.deserialize(proof)
        header = signature.jose_header
        if header.get("typ") != POP_PROOF_TYP or "jwk" not in header:
            raise ValueError("missing typ or embedded jwk")
        # Pin the algorithm and the embedded key type. This is what stops an
        # attacker embedding a symmetric (`oct`) key — whose "public" half is the
        # HMAC secret — and self-signing a valid-looking proof.
        if header.get("alg") != "EdDSA":
            raise ValueError(f"proof alg must be EdDSA, got {header.get('alg')!r}")
        validate_public_ed25519_jwk(header["jwk"])

        embedded = jwk.JWK(**header["jwk"])
        jkt = embedded.thumbprint()
        if jkt != expected_jkt:
            raise ValueError("proof key does not match token cnf.jkt")

        signature.verify(embedded)
        payload = json.loads(signature.payload)

        now = time.time()
        iat = payload.get("iat")
        if not isinstance(iat, int):
            raise ValueError("missing iat")
        if iat > now + _PROOF_CLOCK_SKEW_SECONDS:
            raise ValueError("proof issued in the future")
        if now - iat > _PROOF_MAX_AGE_SECONDS:
            raise ValueError("proof too old")

        if payload.get("htm") != htm.upper():
            raise ValueError("htm mismatch")
        if payload.get("htu") != htu:
            raise ValueError("htu mismatch")
        if payload.get("ath") != access_token_hash(access_token):
            raise ValueError("ath mismatch")
        if not isinstance(payload.get("jti"), str):
            raise ValueError("missing jti")

        # Body binding (proof v2). When the request carries a body, a `cd`
        # claim must be present (if required) and must match the exact bytes.
        if body is not None:
            cd = payload.get("cd")
            if cd is None:
                if require_body_binding:
                    raise ValueError("proof missing cd (body binding required)")
            elif cd != content_digest(body):
                raise ValueError("cd mismatch: proof does not cover this body")
        elif payload.get("cd") is not None:
            raise ValueError("proof carries cd but request has no body")

        return VerifiedPopProof(jti=payload["jti"], jkt=jkt)
    except ToolgateError:
        raise
    except Exception as err:
        raise ToolgateError(
            ErrorCodes.PROOF_INVALID, f"proof-of-possession rejected: {err}"
        ) from err
