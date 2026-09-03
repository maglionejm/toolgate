import json
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from random import random
from typing import Any

from jwcrypto import jwk, jwt
from pydantic import ValidationError

from .errors import ErrorCodes, ToolgateError
from .types import AuthorizationDetail, CapabilityClaims

CAPABILITY_TOKEN_TYP = "tg+jwt"
DEFAULT_TOKEN_TTL_SECONDS = 120


@dataclass(frozen=True)
class MintedToken:
    token: str
    jti: str
    txn: str
    expires_at: datetime


def _jittered_ttl_seconds(ttl_seconds: int) -> float:
    """±15% jitter on the TTL so a harvested batch of tokens never expires at
    the same instant and refresh storms don't synchronize."""
    return max(1.0, ttl_seconds * (1 + (random() * 0.3 - 0.15)))


def mint_capability_token(
    control_plane_private_jwk: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    tenant_id: str,
    user_id: str,
    agent_id: str,
    grant_id: str,
    scopes: list[str],
    authorization_details: list[AuthorizationDetail],
    agent_jkt: str,
    txn: str | None = None,
    ttl_seconds: int | None = None,
) -> MintedToken:
    key = jwk.JWK(**control_plane_private_jwk)
    ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_TOKEN_TTL_SECONDS
    jti = secrets.token_urlsafe(16)
    txn = txn or f"txn_{secrets.token_urlsafe(12)}"

    now = time.time()
    exp = now + (ttl if ttl < 0 else _jittered_ttl_seconds(ttl))

    header: dict[str, Any] = {"alg": "EdDSA", "typ": CAPABILITY_TOKEN_TYP}
    if control_plane_private_jwk.get("kid"):
        header["kid"] = control_plane_private_jwk["kid"]

    token = jwt.JWT(
        header=header,
        claims={
            "iss": issuer,
            "sub": user_id,
            "aud": audience,
            "iat": int(now),
            "exp": int(exp),
            "jti": jti,
            "tenant": tenant_id,
            "grant_id": grant_id,
            "act": {"sub": agent_id},
            "scope": " ".join(scopes),
            "authorization_details": [
                d.model_dump(mode="json") for d in authorization_details
            ],
            "cnf": {"jkt": agent_jkt},
            "txn": txn,
            "tg_ver": 1,
        },
    )
    token.make_signed_token(key)
    return MintedToken(
        token=token.serialize(),
        jti=jti,
        txn=txn,
        expires_at=datetime.fromtimestamp(exp, tz=UTC),
    )


def verify_capability_token(
    control_plane_public_jwk: dict[str, Any],
    token: str,
    *,
    issuer: str,
    audience: str,
    clock_tolerance_seconds: int = 0,
) -> CapabilityClaims:
    key = jwk.JWK(**control_plane_public_jwk)
    verifier = jwt.JWT(
        check_claims={"iss": issuer, "aud": audience, "exp": None, "iat": None, "jti": None}
    )
    verifier.leeway = clock_tolerance_seconds
    try:
        verifier.deserialize(token, key)
    except jwt.JWTExpired as err:
        raise ToolgateError(ErrorCodes.TOKEN_EXPIRED, "capability token expired") from err
    except Exception as err:
        raise ToolgateError(
            ErrorCodes.TOKEN_INVALID, f"capability token rejected: {err}"
        ) from err

    header = json.loads(verifier.header)
    if header.get("typ") != CAPABILITY_TOKEN_TYP:
        raise ToolgateError(ErrorCodes.TOKEN_INVALID, "capability token has wrong typ")

    try:
        return CapabilityClaims.model_validate(json.loads(verifier.claims))
    except ValidationError as err:
        raise ToolgateError(
            ErrorCodes.TOKEN_INVALID,
            "capability token claims malformed",
            {"issues": [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in err.errors()]},
        ) from err
