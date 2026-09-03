import json
from dataclasses import dataclass
from typing import Any

from jwcrypto import jwk


@dataclass(frozen=True)
class KeyPairJwk:
    # RFC 7638 thumbprint of the public JWK; doubles as `kid` and `cnf.jkt`.
    kid: str
    public_jwk: dict[str, Any]
    private_jwk: dict[str, Any]


def generate_ed25519_key_pair() -> KeyPairJwk:
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    kid = key.thumbprint()
    public = json.loads(key.export_public())
    private = json.loads(key.export_private())
    public.update({"kid": kid, "alg": "EdDSA"})
    private.update({"kid": kid, "alg": "EdDSA"})
    return KeyPairJwk(kid=kid, public_jwk=public, private_jwk=private)


# Members that only appear in a private or symmetric key. Their presence in a
# JWK that is meant to be a public verification key means the caller handed us
# secret material — reject outright rather than store it.
_PRIVATE_JWK_MEMBERS = frozenset({"d", "k", "p", "q", "dp", "dq", "qi", "oth"})


def validate_public_ed25519_jwk(candidate: Any) -> None:
    """Enforce the single agent-key invariant: an agent registers exactly one
    *public* Ed25519 (OKP) verification key and nothing else.

    Raises ``ValueError`` for anything else — symmetric (``oct``) keys, EC/RSA
    keys, or a "public" JWK that smuggles private material. Without this an
    attacker can register an ``oct`` key whose public half *is* the shared
    secret and then forge HS256 client assertions and PoP proofs, collapsing
    sender-binding entirely.
    """
    if not isinstance(candidate, dict):
        raise ValueError("public JWK must be a JSON object")
    if candidate.get("kty") != "OKP":
        raise ValueError(f"agent key kty must be 'OKP', got {candidate.get('kty')!r}")
    if candidate.get("crv") != "Ed25519":
        raise ValueError(f"agent key crv must be 'Ed25519', got {candidate.get('crv')!r}")
    x = candidate.get("x")
    if not isinstance(x, str) or not x:
        raise ValueError("agent key must carry a non-empty public 'x' coordinate")
    leaked = _PRIVATE_JWK_MEMBERS.intersection(candidate)
    if leaked:
        raise ValueError(f"public JWK must not contain private members: {sorted(leaked)}")
    if candidate.get("alg", "EdDSA") != "EdDSA":
        raise ValueError(f"agent key alg must be 'EdDSA', got {candidate.get('alg')!r}")


def jwk_thumbprint(public_jwk: dict[str, Any]) -> str:
    return _to_jwk(public_jwk).thumbprint()


def public_jwk_from_private(private_jwk: dict[str, Any]) -> dict[str, Any]:
    """Ed25519 public JWK is the private JWK minus the secret scalar `d` (bare
    RFC 7638 members only, suitable for embedding in proof headers)."""
    return {k: private_jwk[k] for k in ("kty", "crv", "x")}


KeyLike = dict[str, Any] | jwk.JWK


def to_jwk(key: KeyLike) -> jwk.JWK:
    """Coerce a JWK dict into a parsed key. Long-lived callers (server context,
    SDK client) parse once and pass the jwk.JWK through hot paths; dict input
    stays supported for one-shot use."""
    return key if isinstance(key, jwk.JWK) else jwk.JWK(**key)


def _to_jwk(jwk_dict: dict[str, Any]) -> jwk.JWK:
    return jwk.JWK(**jwk_dict)
