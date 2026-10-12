import type { Schemas } from "./api/client";

export type HeaderRow = Schemas["HeadersRow"];
export type Evidence = Schemas["ReportsEvidence"];

/** Previous-seal evidence names its carrying block, and therefore selects
 * the preceding row. Full numbers stay decimal strings, never JS numbers. */
export function evidenceHeight(e: Evidence): string | null {
  if (!e.number || !/^\d+$/.test(e.number)) return null;
  const n = BigInt(e.number);
  if (e.field?.startsWith("extra.prev_")) return n > 0n ? String(n - 1n) : null;
  return String(n);
}

export function included(v: boolean | null): string {
  return v === null ? "unknown" : v ? "included" : "absent";
}

export function pageEnd(start: string, last: string, size = 128): string {
  const end = BigInt(start) + BigInt(size - 1);
  return String(end > BigInt(last) ? BigInt(last) : end);
}

/** A height match alone cannot attach a different fork's evidence. Previous
 * seals are proven by the child; other fields are proven by the row itself. */
export function evidenceMatches(row: HeaderRow, e: Evidence, validator?: string): boolean {
 if (evidenceHeight(e) !== row.fact.number) return false;
 if (row.copy && e.node && row.copy.node !== e.node) return false;
 if (e.hash) {
  const proof = e.field?.startsWith("extra.prev_") ? row.proof_hash : row.fact.hash;
  if (!proof || proof.toLowerCase() !== e.hash.toLowerCase()) return false;
 }
 if (validator && e.address && validator.toLowerCase() !== e.address.toLowerCase()) return false;
 return true;
}
