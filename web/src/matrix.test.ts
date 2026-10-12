import { describe, expect, it } from "vitest";
import type { Schemas } from "./api/client";
import { buildMatrix } from "./matrix";
import { partlyPassed, verdictEncoding } from "./visual";

function report(id: string, finished: string): Schemas["Report"] {
  return {
    id,
    network_id: 1,
    run_id: id,
    started_at: finished,
    finished_at: finished,
    inspector_version: "v",
    inspector_commit: "c",
    catalog_sha256: "x",
    spec_commit: "s",
    network: null,
    range: null,
    summary: {},
    loaded_at: finished,
  };
}

function result(requirement: string, verdict: string, node = ""): Schemas["Result"] {
  return { requirement, node, verdict, coverage: null };
}

describe("buildMatrix", () => {
  it("orders reports by time and rows with failures first, leaving absent cells undefined", () => {
    const later = report("b", "2026-10-12T01:00:00Z");
    const earlier = report("a", "2026-10-12T00:00:00Z");
    const results = new Map([
      ["a", [result("WBFT-SM-011", "PASS"), result("WBFT-SM-012", "PASS"), result("WBFT-SM-012", "FAIL", "0xabc")]],
      ["b", [result("WBFT-SM-011", "PASS"), result("WBFT-SM-012", "FAIL"), result("WBFT-SM-013", "CANNOT_DECIDE")]],
    ]);
    const m = buildMatrix([later, earlier], results);
    expect(m.reports.map((r) => r.id)).toEqual(["a", "b"]);
    expect(m.rows).toEqual([
      { requirement: "WBFT-SM-012", cells: [result("WBFT-SM-012", "PASS"), result("WBFT-SM-012", "FAIL")], fails: 1 },
      { requirement: "WBFT-SM-011", cells: [result("WBFT-SM-011", "PASS"), result("WBFT-SM-011", "PASS")], fails: 0 },
      { requirement: "WBFT-SM-013", cells: [undefined, result("WBFT-SM-013", "CANNOT_DECIDE")], fails: 0 },
    ]);
  });

  it("preserves coverage so a whole-run partly passed result reaches the display", () => {
    const x = { ...result("WBFT-SM-011", "CANNOT_DECIDE"), coverage: { pass: 9824, fail: 0, cannot_decide: 1278 } };
    const node = { ...x, node: "0xabc", coverage: { pass: 0, fail: 0, cannot_decide: 1 } };
    const m = buildMatrix([report("a", "2026-10-12T00:00:00Z")], new Map([["a", [x, node]]]));
    const cell = m.rows[0]?.cells[0];
    expect(cell).toEqual(x);
    expect(verdictEncoding(cell?.verdict, cell?.coverage)).toEqual(partlyPassed);
    expect(m.rows[0]?.fails).toBe(0);
  });
});

describe("verdictEncoding", () => {
  it("hatches what is not known", () => {
    expect(verdictEncoding(undefined).glyph).toBe("hatch");
    expect(verdictEncoding("CANNOT_DECIDE").glyph).toBe("hatch");
    expect(verdictEncoding("SOMETHING_NEW")).toEqual({ label: "something_new", className: "v-unknown", glyph: "hatch" });
    expect(verdictEncoding("FAIL").glyph).toBe("cross");
  });

  it("gives passed and undecided instances their own shape and label", () => {
    expect(verdictEncoding("CANNOT_DECIDE", { pass: 3, fail: 0, cannot_decide: 1 })).toEqual({
      label: "partly passed", className: "v-partly", glyph: "half-disc",
    });
  });

  it.each([
    null, undefined, {}, [], "unknown",
    { pass: 0, fail: 0, cannot_decide: 1 },
    { pass: 1, fail: 0, cannot_decide: 0 },
    { pass: 1, fail: 1, cannot_decide: 1 },
    { pass: 1, cannot_decide: 1 },
    { pass: "1", fail: 0, cannot_decide: 1 },
    { pass: 1, fail: 0, cannot_decide: "1" },
    { pass: -1, fail: 0, cannot_decide: 1 },
    { pass: 1.5, fail: 0, cannot_decide: 1 },
    { pass: 1, fail: 0, cannot_decide: Infinity },
  ])("keeps other or malformed coverage undecided: %j", (coverage) => {
    expect(verdictEncoding("CANNOT_DECIDE", coverage).glyph).toBe("hatch");
  });

  it.each(["PASS", "FAIL", "NOT_RUN", "SOMETHING_NEW", undefined])("keeps the reported verdict %s", (verdict) => {
    const coverage = { pass: 3, fail: 0, cannot_decide: 1 };
    expect(verdictEncoding(verdict, coverage)).toEqual(verdictEncoding(verdict));
  });
});
