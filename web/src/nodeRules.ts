import type { Schemas } from "./api/client";

export type ConfigurationCapture = {
  dataset_id: number;
  name: string;
  snapshot: string;
  source_sha256: string;
  node: Schemas["StoreObservationNode"];
};

export type Agreement = "matching" | "different" | "incomplete";
export type RuleComparison = {
  key: string;
  heights: (string | null)[];
  agreement: Agreement;
};

export function fullHeight(value: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("Use a canonical nonnegative full height.");
  return BigInt(value);
}

function agreement(values: (string | null)[]): Agreement {
  const known = values.filter((value): value is string => value !== null);
  if (new Set(known).size > 1) return "different";
  return known.length === values.length ? "matching" : "incomplete";
}

export function compareNodeRules(captures: ConfigurationCapture[]) {
  if (captures.length < 2 || captures.length > 16) throw new Error("Choose 2–16 observation captures.");
  if (new Set(captures.map((capture) => capture.dataset_id)).size !== captures.length) {
    throw new Error("Choose each observation capture once.");
  }
  const first = captures[0]!.node;
  fullHeight(first.chain_id);
  if (!/^0x[0-9a-f]{64}$/i.test(first.genesis_hash)) throw new Error("Chain identity is unavailable.");
  for (const { node } of captures) {
    fullHeight(node.chain_id);
    fullHeight(node.head_number);
    if (node.chain_id !== first.chain_id || node.genesis_hash.toLowerCase() !== first.genesis_hash.toLowerCase()) {
      throw new Error("Compare captures from the same chain and genesis.");
    }
    for (const value of Object.values(node.rule_activations)) fullHeight(value);
  }
  const digests = captures.map(({ node }) => /^0x[0-9a-f]{64}$/i.test(node.rules_digest) ? node.rules_digest.toLowerCase() : null);
  const keys = [...new Set(captures.flatMap(({ node }) => Object.keys(node.rule_activations)))].sort();
  const rules: RuleComparison[] = keys.map((key) => {
    const heights = captures.map(({ node }) => Object.hasOwn(node.rule_activations, key) ? node.rule_activations[key]! : null);
    return { key, heights, agreement: agreement(heights) };
  });
  const counts = new Map<string, number>();
  for (const { node } of captures) {
    const address = node.address.toLowerCase();
    counts.set(address, (counts.get(address) ?? 0) + 1);
  }
  return {
    digests,
    digestGroups: [...new Set(digests.filter((digest): digest is string => digest !== null))].sort().map((digest) => ({
      digest,
      datasets: captures.filter((_, index) => digests[index] === digest).map((capture) => capture.dataset_id),
    })),
    digestAgreement: agreement(digests),
    rules,
    distinctNodes: counts.size,
    repeatedNodes: [...counts].filter(([, count]) => count > 1).map(([address]) => address),
  };
}

export function declaredActivation(from: string | null, at: string): "not declared" | "active by declaration" | "scheduled by declaration" {
  const height = fullHeight(at);
  if (from === null) return "not declared";
  return fullHeight(from) <= height ? "active by declaration" : "scheduled by declaration";
}
