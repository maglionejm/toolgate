import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Deterministic JSON: keys sorted recursively, compact separators.

    The same logical record always hashes to the same bytes regardless of
    insertion order. `None` values are preserved; callers drop absent fields
    before canonicalization (pydantic `exclude_none`).
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
