import { describe, expect, it } from "vitest";
import { evidenceHeight, included, pageEnd } from "./headers";
describe("header evidence and windows", () => {
 it("keeps full numbers and selects the preceding height of previous-seal evidence", () => {
  expect(evidenceHeight({kind:"block",number:"18446744073709551618",field:"extra.prev_committed_seal.sealers"})).toBe("18446744073709551617");
  expect(evidenceHeight({kind:"block",number:"9",field:"Coinbase"})).toBe("9");
  expect(evidenceHeight({kind:"block",number:"0",field:"extra.prev_prepared_seal"})).toBeNull();
  expect(evidenceHeight({kind:"log"})).toBeNull();
 });
 it("clamps pages without binary64 rounding", () => {expect(pageEnd("18446744073709551400","18446744073709551615")).toBe("18446744073709551527");expect(pageEnd("4","6")).toBe("6")});
 it("does not turn unknown into absent", () => {expect(included(null)).toBe("unknown");expect(included(false)).toBe("absent");expect(included(true)).toBe("included")});
});
