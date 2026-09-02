/**
 * Deterministic JSON serialization: object keys sorted recursively so the same
 * logical record always hashes to the same bytes regardless of insertion order.
 * `undefined` values are dropped (matching JSON.stringify semantics for objects).
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      const v = record[key];
      if (v !== undefined) out[key] = sortValue(v);
    }
    return out;
  }
  return value;
}
