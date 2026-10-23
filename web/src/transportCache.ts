export const cachePolicyFields = ["receive_pending", "receive_per_peer", "write_pending", "write_per_peer"] as const;
type LimitName = typeof cachePolicyFields[number];

export type CachePolicyDeclaration = {
  active: boolean;
  limits: Record<LimitName, string>;
};

function pendingCount(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 20 || !/^[1-9][0-9]*$/.test(value)) return null;
  return BigInt(value) <= 18446744073709551615n ? value : null;
}

/** Declaration parsing never supplies a missing policy or a numeric default. */
export function transportCacheDeclaration(fields: Record<string, unknown>): CachePolicyDeclaration | null {
  if (fields.transport_cache_profile !== "accepted_completed_v1" || typeof fields.transport_cache_active !== "boolean") return null;
  const limits = {} as Record<LimitName, string>;
  for (const key of cachePolicyFields) {
    const value = pendingCount(fields[`transport_cache_${key}`]);
    if (value === null) return null;
    limits[key] = value;
  }
  if (BigInt(limits.receive_per_peer) > BigInt(limits.receive_pending) || BigInt(limits.write_per_peer) > BigInt(limits.write_pending)) return null;
  return { active: fields.transport_cache_active, limits };
}
