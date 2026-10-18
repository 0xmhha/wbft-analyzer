import { expect, it } from "vitest";
import { activationWindows } from "./activationWindows";

it("keeps declared activation windows disjoint and exact above uint64", () => {
  expect(activationWindows("18446744073709551617", "2", "3")).toEqual({ before: { from: "18446744073709551615", to: "18446744073709551616" }, after: { from: "18446744073709551617", to: "18446744073709551619" } });
  expect(activationWindows("1", "50", "2")).toEqual({ before: { from: "0", to: "0" }, after: { from: "1", to: "2" } });
  expect(activationWindows("0", "50", "2")).toEqual({ before: null, after: { from: "0", to: "1" } });
});
it("rejects ambiguous widths, combined oversized intervals and full-height overflow", () => {
  for (const bad of ["0", "01", "-1", "1e2", " 1", "100001", "9999999999999999999999"]) expect(() => activationWindows("1", bad, "2")).toThrow();
  for (const bad of ["01", "", "-1", "1".repeat(157)]) expect(() => activationWindows(bad, "1", "1")).toThrow();
  expect(() => activationWindows("100000", "50001", "50000")).toThrow("100000");
  expect(() => activationWindows("9".repeat(156), "1", "2")).toThrow();
  expect(activationWindows("100000", "50000", "50000").before?.from).toBe("50000");
});
