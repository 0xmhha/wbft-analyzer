import { expect, it } from "vitest";
import { phaseEvidenceLink, phaseHeightRange } from "./phaseComparison";

it("keeps the full-height comparison interval exact above uint64", () => {
  expect(() => phaseHeightRange("18446744073709551617", "18446744073709651616")).not.toThrow();
  expect(() => phaseHeightRange("18446744073709551617", "18446744073709651617")).toThrow("100000");
  expect(() => phaseHeightRange("18446744073709551618", "18446744073709551617")).toThrow("ordered");
  for (const bad of ["01", "-1", "1e5", "", " 1", "1".repeat(157)]) expect(() => phaseHeightRange(bad, "5")).toThrow("canonical");
});
it("uses network-bound original event pointers and rejects unsafe source identities", () => {
  expect(phaseEvidenceLink(7, 2, "node-1.log", 19)).toBe("#/networks/7/events?dataset=2&input=node-1.log&line=19");
  expect(phaseEvidenceLink(7, 2, "../node", 19)).toBeUndefined();
  expect(phaseEvidenceLink(7, 2, "node", Number.MAX_SAFE_INTEGER + 1)).toBeUndefined();
  expect(phaseEvidenceLink(7, 0, "node", 1)).toBeUndefined();
});
