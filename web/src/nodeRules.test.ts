import { describe, expect, it } from "vitest";
import { compareNodeRules, declaredActivation, fullHeight, type ConfigurationCapture } from "./nodeRules";

const hash = (digit: string) => `0x${digit.repeat(64)}`;
function capture(id: number, overrides: Partial<ConfigurationCapture["node"]> = {}): ConfigurationCapture {
  return {
    dataset_id: id, name: `Synthetic capture ${id}`, snapshot: hash("a"), source_sha256: "b".repeat(64),
    node: {
      address: `0x${String(id).padStart(40, "0")}`, bls_public_key: "", build: "synthetic", chain_id: "1",
      genesis_hash: hash("1"), head_hash: hash("2"), head_number: "10", impl: "wbft", improvements: [],
      log_profile: "synthetic", mode: "standalone", rule_activations: { limit: "0" },
      rules_digest: hash("3"), sign_floor: "", validator: true, version: "v1", ...overrides,
    },
  };
}

describe("reported node rule comparisons", () => {
  it("exposes one different reported digest and activation in a seven-node selection", () => {
    const captures = Array.from({ length: 7 }, (_, i) => capture(i + 1));
    captures[4] = capture(5, { rules_digest: hash("4"), rule_activations: { limit: "11" } });
    const result = compareNodeRules(captures);
    expect(result.digestAgreement).toBe("different");
    expect(result.rules).toEqual([{ key: "limit", heights: ["0", "0", "0", "0", "11", "0", "0"], agreement: "different" }]);
    expect(result.distinctNodes).toBe(7);
    expect(result.digestGroups).toEqual([
      { digest: hash("3"), datasets: [1, 2, 3, 4, 6, 7] },
      { digest: hash("4"), datasets: [5] },
    ]);
  });

  it("keeps absent declarations separate from height zero and missing digests separate from matching ones", () => {
    const result = compareNodeRules([capture(1), capture(2, { rule_activations: {}, rules_digest: "" })]);
    expect(result.digestAgreement).toBe("incomplete");
    expect(result.rules[0]).toEqual({ key: "limit", heights: ["0", null], agreement: "incomplete" });
    expect(declaredActivation("0", "0")).toBe("active by declaration");
    expect(declaredActivation(null, "0")).toBe("not declared");
  });

  it("compares full activation heights exactly above uint64 and at their boundary", () => {
    const height = "18446744073709551617";
    const result = compareNodeRules([capture(1, { rule_activations: { limit: height } }), capture(2, { rule_activations: { limit: "18446744073709551618" } })]);
    expect(result.rules[0]?.agreement).toBe("different");
    expect(declaredActivation(height, "18446744073709551616")).toBe("scheduled by declaration");
    expect(declaredActivation(height, height)).toBe("active by declaration");
  });

  it("rejects cross-chain and cross-genesis selections", () => {
    expect(() => compareNodeRules([capture(1), capture(2, { chain_id: "2" })])).toThrow("same chain");
    expect(() => compareNodeRules([capture(1), capture(2, { genesis_hash: hash("2") })])).toThrow("same chain");
  });

  it("identifies repeated node snapshots without treating their heads as simultaneous observations", () => {
    const a = capture(1);
    const b = capture(2, { address: a.node.address, head_number: "11", head_hash: hash("5") });
    const result = compareNodeRules([a, b]);
    expect(result.distinctNodes).toBe(1);
    expect(result.repeatedNodes).toEqual([a.node.address]);
    expect(result.digestAgreement).toBe("matching");
  });

  it("retains a reported zero digest and reports differences even with an additional missing capture", () => {
    expect(compareNodeRules([capture(1, { rules_digest: hash("0") }), capture(2, { rules_digest: hash("0") })]).digestAgreement).toBe("matching");
    expect(compareNodeRules([capture(1), capture(2, { rules_digest: hash("4") }), capture(3, { rules_digest: "" })]).digestAgreement).toBe("different");
  });

  it("rejects duplicate selections, out-of-bound selection sizes and malformed full heights", () => {
    expect(() => compareNodeRules([capture(1), capture(1)])).toThrow("once");
    expect(() => compareNodeRules([capture(1)])).toThrow("2–16");
    expect(() => compareNodeRules(Array.from({ length: 17 }, (_, i) => capture(i + 1)))).toThrow("2–16");
    for (const bad of ["-1", "01", "1e2", "", " 1", "1.0"]) expect(() => fullHeight(bad)).toThrow("canonical");
    expect(() => compareNodeRules([capture(1), capture(2, { rule_activations: { limit: "01" } })])).toThrow("canonical");
  });
});
