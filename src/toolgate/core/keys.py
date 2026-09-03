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


def jwk_thumbprint(public_jwk: dict[str, Any]) -> str:
    return _to_jwk(public_jwk).thumbprint()


def public_jwk_from_private(private_jwk: dict[str, Any]) -> dict[str, Any]:
    """Ed25519 public JWK is the private JWK minus the secret scalar `d` (bare
    RFC 7638 members only, suitable for embedding in proof headers)."""
    return {k: private_jwk[k] for k in ("kty", "crv", "x")}


def _to_jwk(jwk_dict: dict[str, Any]) -> jwk.JWK:
    return jwk.JWK(**jwk_dict)
