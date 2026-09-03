import secrets
from typing import Literal

# Crockford-style base32, lowercase, without ambiguous characters (i, l, o, u).
_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"

IdPrefix = Literal["tnt", "usr", "agt", "ups", "grt", "pol", "apr", "call", "evt"]


def new_id(prefix: IdPrefix, size: int = 20) -> str:
    """20 chars over a 32-symbol alphabet ~= 100 bits of entropy."""
    body = "".join(_ALPHABET[b % 32] for b in secrets.token_bytes(size))
    return f"{prefix}_{body}"
