import { describe, expect, it } from "vitest";
import type { Schemas } from "./api/client";
import { buildMatrix } from "./matrix";
import { verdictEncoding } from "./visual";

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
      { requirement: "WBFT-SM-012", cells: ["PASS", "FAIL"], fails: 1 },
      { requirement: "WBFT-SM-011", cells: ["PASS", "PASS"], fails: 0 },
      { requirement: "WBFT-SM-013", cells: [undefined, "CANNOT_DECIDE"], fails: 0 },
    ]);
  });
});

describe("verdictEncoding", () => {
  it("hatches what is not known", () => {
    expect(verdictEncoding(undefined).glyph).toBe("hatch");
    expect(verdictEncoding("CANNOT_DECIDE").glyph).toBe("hatch");
    expect(verdictEncoding("SOMETHING_NEW")).toEqual({ label: "something_new", className: "v-unknown", glyph: "hatch" });
    expect(verdictEncoding("FAIL").glyph).toBe("cross");
  });
});
