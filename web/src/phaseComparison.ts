import { eventFocus } from "./sourceLink";

export function phaseHeightRange(from: string, to: string): void {
  if (![from, to].every((value) => /^(0|[1-9][0-9]{0,155})$/.test(value))) throw new Error("Use canonical nonnegative full heights.");
  const first = BigInt(from), last = BigInt(to);
  if (last < first || last - first >= 100000n) throw new Error("Choose an ordered range of at most 100000 heights.");
}

export function phaseEvidenceLink(net: number, dataset: number, input: string, line: number): string | undefined {
  if (!Number.isSafeInteger(net) || net < 1) return undefined;
  const query = new URLSearchParams({ dataset: String(dataset), input, line: String(line) });
  return eventFocus(query.toString()).focus ? `#/networks/${net}/events?${query}` : undefined;
}
