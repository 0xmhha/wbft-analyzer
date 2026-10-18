import { phaseHeightRange } from "./phaseComparison";

export function activationWindows(from: string, before: string, after: string): { before: { from: string; to: string } | null; after: { from: string; to: string } } {
  phaseHeightRange(from, from);
  for (const width of [before, after]) if (!/^[1-9][0-9]{0,5}$/.test(width) || Number(width) > 100000) throw new Error("Use canonical positive window sizes up to 100000 heights.");
  const activation = BigInt(from), first = activation > BigInt(before) ? activation - BigInt(before) : 0n, last = activation + BigInt(after) - 1n;
  phaseHeightRange(first.toString(), last.toString());
  return { before: activation === 0n ? null : { from: first.toString(), to: (activation - 1n).toString() }, after: { from, to: last.toString() } };
}
